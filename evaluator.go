package main

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"regexp"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	// Tempo de vida do cache em segundos
	CACHE_TTL = 30 * time.Second
)

// nomeFlagValido restringe o que pode virar caminho de URL nas chamadas aos outros
// serviços (allowlist). O gosec apontou risco de SSRF (G704) porque o nome da flag
// vem do usuário: validamos o formato e escapamos o valor antes de montar a URL.
var nomeFlagValido = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,100}$`)

// ErrFlagInvalida é devolvido quando o nome da flag não passa na allowlist.
var ErrFlagInvalida = errors.New("nome de flag inválido")

// validarNomeFlag protege as chamadas HTTP contra injeção de caminho/host.
func validarNomeFlag(flagName string) error {
	if !nomeFlagValido.MatchString(flagName) {
		return fmt.Errorf("%w: %q", ErrFlagInvalida, flagName)
	}
	return nil
}

// getDecision é o wrapper principal
func (a *App) getDecision(reqCtx context.Context, userID, flagName string) (bool, error) {
	// 1. Obter os dados da flag (do cache ou dos serviços)
	info, err := a.getCombinedFlagInfo(reqCtx, flagName)
	if err != nil {
		return false, err
	}

	// 2. Executar a lógica de avaliação
	return a.runEvaluationLogic(info, userID), nil
}

// redisSpan abre um span de cliente para uma operação no Redis.
// O go-redis v8 não tem instrumentação OTel compatível com o SDK atual, então o span é manual.
func redisSpan(reqCtx context.Context, operation, key string) (context.Context, trace.Span) {
	return tracer.Start(reqCtx, "redis "+operation,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("db.system", "redis"),
			attribute.String("db.operation", operation),
			attribute.String("db.redis.key", key),
		),
	)
}

// getCombinedFlagInfo busca os dados no Redis, com fallback para os microsserviços
func (a *App) getCombinedFlagInfo(reqCtx context.Context, flagName string) (*CombinedFlagInfo, error) {
	cacheKey := fmt.Sprintf("flag_info:%s", flagName)

	// 1. Tentar buscar do Cache (Redis)
	spanCtx, span := redisSpan(reqCtx, "GET", cacheKey)
	val, err := a.RedisClient.Get(spanCtx, cacheKey).Result()
	span.SetAttributes(attribute.Bool("cache.hit", err == nil))
	span.End()
	if err == nil {
		// Cache HIT
		var info CombinedFlagInfo
		if err := json.Unmarshal([]byte(val), &info); err == nil {
			log.Printf("Cache HIT para flag '%s'", flagName)
			return &info, nil
		}
		// Se o unmarshal falhar, trata como cache miss
		log.Printf("Erro ao desserializar cache para flag '%s': %v", flagName, err)
	}

	log.Printf("Cache MISS para flag '%s'", flagName)
	// 2. Cache MISS - Buscar dos serviços
	info, err := a.fetchFromServices(reqCtx, flagName)
	if err != nil {
		return nil, err
	}

	// 3. Salvar no Cache
	jsonData, err := json.Marshal(info)
	if err == nil {
		spanCtx, span := redisSpan(reqCtx, "SET", cacheKey)
		a.RedisClient.Set(spanCtx, cacheKey, jsonData, CACHE_TTL).Err()
		span.End()
	}

	return info, nil
}

// fetchFromServices busca dados do flag-service e targeting-service concorrentemente
func (a *App) fetchFromServices(reqCtx context.Context, flagName string) (*CombinedFlagInfo, error) {
	var wg sync.WaitGroup
	wg.Add(2)

	var flagInfo *Flag
	var ruleInfo *TargetingRule
	var flagErr, ruleErr error

	// Goroutine 1: Buscar do flag-service
	go func() {
		defer wg.Done()
		flagInfo, flagErr = a.fetchFlag(reqCtx, flagName)
	}()

	// Goroutine 2: Buscar do targeting-service
	go func() {
		defer wg.Done()
		ruleInfo, ruleErr = a.fetchRule(reqCtx, flagName)
	}()

	wg.Wait()

	if flagErr != nil {
		return nil, flagErr
	}
	if ruleErr != nil {
		log.Printf("Aviso: Nenhuma regra de segmentação encontrada para '%s'. Usando padrão.", flagName)
	}

	return &CombinedFlagInfo{
		Flag: flagInfo,
		Rule: ruleInfo,
	}, nil
}

// fetchFlag (função helper)
func (a *App) fetchFlag(reqCtx context.Context, flagName string) (*Flag, error) {
	if err := validarNomeFlag(flagName); err != nil {
		return nil, err
	}
	// A base vem da configuração (FLAG_SERVICE_URL); só o último segmento é do usuário,
	// já validado pela allowlist e escapado aqui.
	endpoint := fmt.Sprintf("%s/flags/%s", a.FlagServiceURL, neturl.PathEscape(flagName))

	apiKey := os.Getenv("SERVICE_API_KEY")
	// O contexto do request carrega o trace; o transport do otelhttp propaga o traceparent.
	req, _ := http.NewRequestWithContext(reqCtx, "GET", endpoint, nil) // #nosec G704 -- host fixo por config + allowlist no nome da flag
	req.Header.Set("Authorization", "Bearer "+apiKey)

	// #nosec G704 -- URL montada acima: host fixo (config) + nome da flag validado por allowlist
	resp, err := a.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erro ao chamar flag-service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, &NotFoundError{flagName}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("flag-service retornou status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var flag Flag
	if err := json.Unmarshal(body, &flag); err != nil {
		return nil, fmt.Errorf("erro ao desserializar resposta do flag-service: %w", err)
	}
	return &flag, nil
}

func (a *App) fetchRule(reqCtx context.Context, flagName string) (*TargetingRule, error) {
	if err := validarNomeFlag(flagName); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/rules/%s", a.TargetingServiceURL, neturl.PathEscape(flagName))
	apiKey := os.Getenv("SERVICE_API_KEY")                             // Usa a mesma chave
	req, _ := http.NewRequestWithContext(reqCtx, "GET", endpoint, nil) // #nosec G704 -- host fixo por config + allowlist no nome da flag
	req.Header.Set("Authorization", "Bearer "+apiKey)

	// #nosec G704 -- URL montada acima: host fixo (config) + nome da flag validado por allowlist
	resp, err := a.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("erro ao chamar targeting-service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, &NotFoundError{flagName} // Não é um erro fatal
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("targeting-service retornou status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var rule TargetingRule
	if err := json.Unmarshal(body, &rule); err != nil {
		return nil, fmt.Errorf("erro ao desserializar resposta do targeting-service: %w", err)
	}
	return &rule, nil
}

// recordError marca o span atual do request como erro, para o APM destacar a falha no trace.
func recordError(reqCtx context.Context, err error) {
	span := trace.SpanFromContext(reqCtx)
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// runEvaluationLogic é onde a decisão é tomada
func (a *App) runEvaluationLogic(info *CombinedFlagInfo, userID string) bool {
	if info.Flag == nil || !info.Flag.IsEnabled {
		return false
	}

	if info.Rule == nil || !info.Rule.IsEnabled {
		return true
	}

	// 3. Processa a regra (só temos "PERCENTAGE" por enquanto)
	rule := info.Rule.Rules
	if rule.Type == "PERCENTAGE" {
		// Converte o 'value' (que é interface{}) para float64
		percentage, ok := rule.Value.(float64)
		if !ok {
			log.Printf("Erro: valor da regra de porcentagem não é um número para a flag '%s'", info.Flag.Name)
			return false
		}

		// Calcula o "bucket" do usuário (0-99)
		userBucket := getDeterministicBucket(userID + info.Flag.Name)

		if float64(userBucket) < percentage {
			return true
		}
	}

	return false
}

func getDeterministicBucket(input string) int {
	// Usamos SHA1 (rápido) e pegamos os primeiros 4 bytes
	hasher := sha1.New()
	hasher.Write([]byte(input))
	hash := hasher.Sum(nil)

	// Converte 4 bytes para um uint32
	val := binary.BigEndian.Uint32(hash[:4])

	// Retorna o módulo 100
	return int(val % 100)
}
