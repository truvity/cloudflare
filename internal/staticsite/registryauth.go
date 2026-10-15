package staticsite

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/errcode"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// Registry authentication methods. The values of STATIC_SITE_REGISTRY_AUTH
// are RegistryAuthAuto (unset), RegistryAuthDockerConfig, RegistryAuthECR and
// RegistryAuthNone; the methods a pull can end up using are the Method*
// names, which are also what is logged.
const (
	RegistryAuthAuto         = "auto"
	RegistryAuthDockerConfig = "dockerconfig"
	RegistryAuthECR          = "ecr"
	RegistryAuthNone         = "none"

	methodDockerConfig = "dockerconfig"
	methodECR          = "ecr-sdk"
	methodAnonymous    = "anonymous"
)

// ecrTokenLifetime is what ECR documents; it is used only when the response
// carries no expiry.
const ecrTokenLifetime = 12 * time.Hour

// ECRAPI is the part of the ECR client the server uses. It is the seam tests
// fill with a fake.
type ECRAPI interface {
	GetAuthorizationToken(ctx context.Context, in *ecr.GetAuthorizationTokenInput, opts ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// ecrHost is what an ECR registry host name says about the registry.
type ecrHost struct {
	Region string
	FIPS   bool
}

// ecrHostRE matches <account>.dkr.ecr[-fips].<region>.amazonaws.com, and the
// China partition's .amazonaws.com.cn.
var ecrHostRE = regexp.MustCompile(`^[0-9]{12}\.dkr\.ecr(-fips)?\.([a-z]{2}(?:-[a-z]+)+-[0-9]+)\.amazonaws\.com(?:\.cn)?$`)

// parseECRHost reports whether host (no port) is an ECR registry.
func parseECRHost(host string) (ecrHost, bool) {
	m := ecrHostRE.FindStringSubmatch(host)
	if m == nil {
		return ecrHost{}, false
	}
	return ecrHost{Region: m[2], FIPS: m[1] != ""}, true
}

// ecrToken is one decoded authorization token.
type ecrToken struct {
	user, pass string
	fetched    time.Time
	expires    time.Time
}

// refreshAt is the half-life of the token.
func (t *ecrToken) refreshAt() time.Time {
	return t.fetched.Add(t.expires.Sub(t.fetched) / 2)
}

// ecrTokenSource fetches ECR authorization tokens and caches the current one.
// It is safe for concurrent use. The token is never logged.
type ecrTokenSource struct {
	api ECRAPI
	now func() time.Time
	log *slog.Logger

	mu  sync.Mutex
	tok *ecrToken
}

// get returns the cached token, fetching a new one when none is cached or the
// cached one is past half of its life. A failed refresh keeps the old token
// while it has not expired.
func (s *ecrTokenSource) get(ctx context.Context) (user, pass string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.tok != nil && now.Before(s.tok.refreshAt()) {
		return s.tok.user, s.tok.pass, nil
	}
	tok, ferr := s.fetch(ctx, now)
	if ferr != nil {
		if s.tok != nil && now.Before(s.tok.expires) {
			s.log.Warn("ecr token refresh failed, using the current token", "error", ferr)
			return s.tok.user, s.tok.pass, nil
		}
		return "", "", ferr
	}
	s.tok = tok
	return tok.user, tok.pass, nil
}

// invalidate drops the cached token (the registry refused it).
func (s *ecrTokenSource) invalidate() {
	s.mu.Lock()
	s.tok = nil
	s.mu.Unlock()
}

func (s *ecrTokenSource) fetch(ctx context.Context, now time.Time) (*ecrToken, error) {
	out, err := s.api.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("ecr GetAuthorizationToken: %w", err)
	}
	if len(out.AuthorizationData) == 0 || out.AuthorizationData[0].AuthorizationToken == nil {
		return nil, errors.New("ecr GetAuthorizationToken: no authorization data in the response")
	}
	d := out.AuthorizationData[0]
	raw, err := base64.StdEncoding.DecodeString(*d.AuthorizationToken)
	if err != nil {
		// Do not wrap err: it could echo the token.
		return nil, errors.New("ecr authorization token is not base64")
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok || user == "" || pass == "" {
		return nil, errors.New("ecr authorization token is not user:password")
	}
	exp := now.Add(ecrTokenLifetime)
	if d.ExpiresAt != nil && d.ExpiresAt.After(now) {
		exp = *d.ExpiresAt
	}
	return &ecrToken{user: user, pass: pass, fetched: now, expires: exp}, nil
}

// registryAuth decides, once per pull, how to authenticate to the registry of
// the artifact, and keeps the ECR token between pulls.
//
// Precedence in auto: a configured Docker config file, then ECR through the
// AWS SDK default credential chain for an ECR host, then anonymous.
type registryAuth struct {
	cfg *Config
	log *slog.Logger

	// Seams for tests.
	parseHost func(host string) (ecrHost, bool)
	newAPI    func(ctx context.Context, h ecrHost) (ECRAPI, error)
	now       func() time.Time

	mu  sync.Mutex
	src *ecrTokenSource
}

func newRegistryAuth(cfg *Config, log *slog.Logger) *registryAuth {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &registryAuth{cfg: cfg, log: log, parseHost: parseECRHost, newAPI: defaultECRAPI, now: time.Now}
}

// defaultECRAPI builds an ECR client from the SDK default credential chain
// (env, web identity / IRSA, container credentials / EKS Pod Identity, ...).
func defaultECRAPI(ctx context.Context, h ecrHost) (ECRAPI, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(h.Region)}
	if h.FIPS {
		opts = append(opts, awsconfig.WithUseFIPSEndpoint(aws.FIPSEndpointStateEnabled))
	}
	c, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return ecr.NewFromConfig(c), nil
}

// dockerConfigConfigured reports whether a Docker config file is configured:
// DOCKER_CONFIG is set (the chart mounts the pull secret there), or
// ~/.docker/config.json exists.
func dockerConfigConfigured(cfg *Config) bool {
	if cfg.DockerConfigDir != "" {
		return true
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(home, ".docker", "config.json"))
	return err == nil
}

// resolve picks the method for registryHost (host[:port]).
func (a *registryAuth) resolve(registryHost string) (method string, h ecrHost, err error) {
	h, isECR := a.parseHost(hostOnly(registryHost))
	switch a.cfg.RegistryAuth {
	case RegistryAuthDockerConfig:
		return methodDockerConfig, h, nil
	case RegistryAuthNone:
		return methodAnonymous, h, nil
	case RegistryAuthECR:
		if !isECR {
			return "", h, fmt.Errorf("registry auth ecr: %q is not an ECR registry host", hostOnly(registryHost))
		}
		return methodECR, h, nil
	}
	switch {
	case dockerConfigConfigured(a.cfg):
		return methodDockerConfig, h, nil
	case isECR:
		return methodECR, h, nil
	}
	return methodAnonymous, h, nil
}

func hostOnly(hostport string) string {
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 && !strings.Contains(hostport[i:], "]") {
		return hostport[:i]
	}
	return hostport
}

// source returns the token source, building the SDK client on first use.
func (a *registryAuth) source(ctx context.Context, h ecrHost) (*ecrTokenSource, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.src != nil {
		return a.src, nil
	}
	api, err := a.newAPI(ctx, h)
	if err != nil {
		return nil, err
	}
	a.src = &ecrTokenSource{api: api, now: a.now, log: a.log}
	return a.src, nil
}

// client returns the auth client for a pull from registryHost and the method
// it uses. Credentials are looked up per request, so a token that has passed
// half of its life is replaced between two requests of one pull.
func (a *registryAuth) client(ctx context.Context, registryHost string) (*auth.Client, string, error) {
	method, h, err := a.resolve(registryHost)
	if err != nil {
		return nil, "", err
	}
	client := &auth.Client{Client: retry.DefaultClient, Cache: auth.NewCache()}
	switch method {
	case methodDockerConfig:
		if store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{}); err == nil {
			client.Credential = credentials.Credential(store)
		}
	case methodECR:
		src, err := a.source(ctx, h)
		if err != nil {
			return nil, "", err
		}
		// Fail now, not on the first 401: a missing identity should read as
		// that, not as "unauthorized".
		if _, _, err := src.get(ctx); err != nil {
			return nil, "", err
		}
		client.Credential = func(ctx context.Context, hostport string) (auth.Credential, error) {
			// Only the artifact's own registry gets the token.
			if hostport != registryHost {
				return auth.EmptyCredential, nil
			}
			user, pass, err := src.get(ctx)
			if err != nil {
				return auth.EmptyCredential, err
			}
			return auth.Credential{Username: user, Password: pass}, nil
		}
	}
	return client, method, nil
}

// refused drops the cached ECR token after the registry answered 401, so the
// next client fetches a new one. It reports whether a retry can help.
func (a *registryAuth) refused(err error, method string) bool {
	if method != methodECR {
		return false
	}
	var er *errcode.ErrorResponse
	if !errors.As(err, &er) || er.StatusCode != http.StatusUnauthorized {
		return false
	}
	a.mu.Lock()
	src := a.src
	a.mu.Unlock()
	if src == nil {
		return false
	}
	src.invalidate()
	return true
}
