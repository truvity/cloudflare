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
	"strconv"
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

// The chart's ACK Policy (charts/static-site-infra/templates/ack.yaml) writes the
// actions out; its rendered golden must carry exactly the Go lists. The
// golden itself is checked against `helm template` by hack/golden.sh.
func TestChartPolicyCarriesTheGoLists(t *testing.T) {
	for _, name := range []string{"ack", "ack-pinned"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "golden", "static-site-infra", name+".yaml"))
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

// The identity is static-site-infra's: role, then binding, then account in
// strictly increasing sync waves, the account guarded against prune and
// delete. The application chart renders neither the account nor any ACK
// object, and renders the identity check as a pre-install,pre-upgrade hook
// Job that never restarts a pod.
func TestIdentityIsSplitAcrossTheTwoCharts(t *testing.T) {
	type object struct {
		Kind     string `yaml:"kind"`
		Metadata struct {
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"metadata"`
		Spec struct {
			Template struct {
				Spec struct {
					RestartPolicy string `yaml:"restartPolicy"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	load := func(chart, name string) []object {
		raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "golden", chart, name+".yaml"))
		require.NoError(t, err)
		var out []object
		for _, part := range strings.Split(string(raw), "\n---\n") {
			var obj object
			require.NoError(t, yaml.Unmarshal([]byte(part), &obj))
			if obj.Kind != "" {
				out = append(out, obj)
			}
		}
		return out
	}

	waves := map[string]int{}
	var account object
	for _, o := range load("static-site-infra", "ack") {
		w, err := strconv.Atoi(o.Metadata.Annotations["argocd.argoproj.io/sync-wave"])
		require.NoError(t, err, "%s has no sync wave", o.Kind)
		waves[o.Kind] = w
		if o.Kind == "ServiceAccount" {
			account = o
		}
	}
	assert.Less(t, waves["Policy"], waves["Role"])
	assert.Less(t, waves["Role"], waves["PodIdentityAssociation"])
	assert.Less(t, waves["PodIdentityAssociation"], waves["ServiceAccount"])
	assert.Equal(t, "Prune=false,Delete=false", account.Metadata.Annotations["argocd.argoproj.io/sync-options"])
	// The Policy is identified in AWS by its ARN, so adoption needs it spelled out;
	// the Role (by name) and the association take no adoption-fields.
	for _, o := range load("static-site-infra", "ack-pinned") {
		fields, has := o.Metadata.Annotations["services.k8s.aws/adoption-fields"]
		if o.Kind == "Policy" {
			assert.JSONEq(t, `{"arn":"arn:aws:iam::123456789012:policy/example-static-www"}`, fields)
		} else {
			assert.False(t, has, "%s must not carry adoption-fields", o.Kind)
		}
	}
	// The ACK objects carry the same guard: the old Application's prune must not delete the Role.
	for _, o := range load("static-site-infra", "ack") {
		assert.Equal(t, "Prune=false,Delete=false", o.Metadata.Annotations["argocd.argoproj.io/sync-options"],
			"%s lacks the prune/delete guard", o.Kind)
		// Policy and Role adopt an object already in AWS; the association never does.
		adoption, adopts := o.Metadata.Annotations["services.k8s.aws/adoption-policy"]
		switch o.Kind {
		case "Policy", "Role":
			assert.Equal(t, "adopt-or-create", adoption, "%s lacks the adoption policy", o.Kind)
		default:
			assert.False(t, adopts, "%s must not be adopted", o.Kind)
		}
	}

	var job *object
	for _, o := range load("static-site", "identity-managed") {
		assert.NotContains(t, []string{"ServiceAccount", "Policy", "Role", "PodIdentityAssociation"}, o.Kind,
			"the application chart renders the identity's %s", o.Kind)
		if o.Kind == "Job" {
			job = &o
		}
	}
	require.NotNil(t, job, "the application chart renders no identity check")
	assert.Equal(t, "pre-install,pre-upgrade", job.Metadata.Annotations["helm.sh/hook"])
	assert.Equal(t, "Never", job.Spec.Template.Spec.RestartPolicy)

	// Without a managed identity the check is not rendered and the chart keeps its account.
	var kinds []string
	for _, o := range load("static-site", "identity-unmanaged-ack-off") {
		kinds = append(kinds, o.Kind)
	}
	assert.Contains(t, kinds, "ServiceAccount")
	assert.NotContains(t, kinds, "Job")
}
