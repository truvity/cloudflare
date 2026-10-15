package staticsite

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every method of the ECR seam is an ECR API call the server makes; each must
// be granted, and account-wide when it takes no resource.
func TestECRAPIMethodsAreGranted(t *testing.T) {
	typ := reflect.TypeFor[ECRAPI]()
	require.Positive(t, typ.NumMethod())
	granted := append(ECRAccountActions(), ECRRepositoryActions()...)
	for i := range typ.NumMethod() {
		assert.Contains(t, granted, "ecr:"+typ.Method(i).Name,
			"ECRAPI.%s is called by the server but no action in ECRAccountActions/ECRRepositoryActions covers it", typ.Method(i).Name)
	}
	// GetAuthorizationToken is the one call without a resource.
	assert.Equal(t, []string{"ecr:GetAuthorizationToken"}, ECRAccountActions())
	assert.NotContains(t, ECRRepositoryActions(), "ecr:GetAuthorizationToken")
}

var (
	manifestPath = regexp.MustCompile(`^/v2/.+/manifests/[^/]+$`)
	blobPath     = regexp.MustCompile(`^/v2/.+/blobs/[^/]+$`)
)

// registryActions is what ECR's registry endpoint checks for a request the
// OCI client makes; an unknown request is a new call the lists must be
// reviewed for.
func registryActions(r *http.Request) ([]string, bool) {
	switch {
	case r.URL.Path == "/v2/" || r.URL.Path == "/v2":
		return nil, true // the version check; ECR answers it with the token alone
	case (r.Method == http.MethodGet || r.Method == http.MethodHead) && manifestPath.MatchString(r.URL.Path):
		return []string{"ecr:BatchGetImage"}, true
	case (r.Method == http.MethodGet || r.Method == http.MethodHead) && blobPath.MatchString(r.URL.Path):
		return []string{"ecr:GetDownloadUrlForLayer"}, true
	}
	return nil, false
}

// A pull makes these registry requests and no others; each needs an action
// the repository list carries.
func TestPullRequestsAreCoveredByTheRepositoryActions(t *testing.T) {
	backend, dgst := siteRegistry(t)
	u, err := url.Parse("http://" + backend)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(u)
	var mu sync.Mutex
	var seen []string
	var unknown []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		acts, ok := registryActions(r)
		if !ok {
			unknown = append(unknown, r.Method+" "+r.URL.Path)
		}
		seen = append(seen, acts...)
		mu.Unlock()
		proxy.ServeHTTP(w, r)
	}))
	defer srv.Close()

	cfg := pullCfg(strings.TrimPrefix(srv.URL, "http://"), "", dgst)
	_, err = Pull(t.Context(), cfg, t.TempDir())
	require.NoError(t, err)

	assert.Empty(t, unknown, "the pull made requests the action lists were not reviewed for")
	assert.Contains(t, seen, "ecr:BatchGetImage", "the pull fetched no manifest")
	assert.Contains(t, seen, "ecr:GetDownloadUrlForLayer", "the pull fetched no layer")
	repo := ECRRepositoryActions()
	for _, a := range seen {
		assert.True(t, slices.Contains(repo, a), "%s is needed by the pull and missing from ECRRepositoryActions", a)
	}
}

// The chart's ACK Policy (charts/static-site/templates/ack.yaml) writes the
// actions out; its rendered golden must carry exactly the Go lists. The
// golden itself is checked against `helm template` by hack/golden.sh.
func TestChartPolicyCarriesTheGoLists(t *testing.T) {
	for _, name := range []string{"ack", "ack-pinned"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "golden", "static-site", name+".yaml"))
			require.NoError(t, err)
			var policy string
			for _, part := range strings.Split(string(raw), "\n---\n") {
				var obj struct {
					Kind string `yaml:"kind"`
					Spec struct {
						PolicyDocument string `yaml:"policyDocument"`
					} `yaml:"spec"`
				}
				require.NoError(t, yaml.Unmarshal([]byte(part), &obj))
				if obj.Kind == "Policy" {
					policy = obj.Spec.PolicyDocument
				}
			}
			require.NotEmpty(t, policy, "the golden renders no ACK Policy")

			var doc struct {
				Statement []struct {
					Effect   string
					Action   []string
					Resource any
				}
			}
			require.NoError(t, json.Unmarshal([]byte(policy), &doc))
			require.Len(t, doc.Statement, 2)
			for _, s := range doc.Statement {
				assert.Equal(t, "Allow", s.Effect)
			}
			assert.Equal(t, ECRAccountActions(), doc.Statement[0].Action)
			assert.Equal(t, "*", doc.Statement[0].Resource)
			assert.Equal(t, ECRRepositoryActions(), doc.Statement[1].Action)
			assert.NotEqual(t, "*", doc.Statement[1].Resource)
		})
	}
}
