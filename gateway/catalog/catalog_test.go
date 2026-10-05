package catalog_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/truvity/gateway/catalog"
)

const fixture = `
version: 1
exposures:
  public:
    class: edge
    arrival: cloudflare-tunnel
    project_groups:
      overrides:
        dev:
          shop:
            group: shop-primary
            description: The shop.
            names:
              shop.dev.example.com: {listener_name: shop, secret_name: shop-tls}
    clusters:
      dev:
        groups:
          shop:
            domains: ["*.shop.dev.example.com"]
            route_namespaces: [shop]
            listener_set: true
          console:
            domains: [console.dev.example.com]
            route_namespaces: [console]
            listener_set: true
      prod:
        groups:
          console:
            domains: [console.prod.example.com]
            route_namespaces: [console]
            listener_set: true
`

var projects = []catalog.Project{
	{Name: "shop", Endpoints: []catalog.Endpoint{
		{Environment: "dev", Hostname: "shop.dev.example.com"},
		{Environment: "prod", Hostname: "shop.prod.example.com"},
	}},
	{Name: "api", Endpoints: []catalog.Endpoint{
		{Environment: "dev", Hostname: "api.dev.example.com"},
		{Environment: "dev", Hostname: "ssi.dev.example.com"},
	}},
	{Name: "idle"},
}

func load(t *testing.T, doc string) *catalog.Config {
	t.Helper()

	c, err := catalog.Load(fstest.MapFS{catalog.FileName: {Data: []byte(doc)}})
	if err != nil {
		t.Fatal(err)
	}

	return c
}

func TestWithProjectsGeneratesOneGroupPerProjectPerCluster(t *testing.T) {
	c := load(t, fixture)
	if err := c.WithProjects(projects); err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, g := range c.Groups("public", "dev") {
		names = append(names, g.Name)
	}

	if got, want := strings.Join(names, ","), "api,console,shop,shop-primary"; got != want {
		t.Fatalf("dev groups = %s, want %s", got, want)
	}

	api := c.Groups("public", "dev")[0]
	if got := strings.Join(api.Hosts(), ","); got != "api.dev.example.com,ssi.dev.example.com" {
		t.Errorf("api hosts = %s (endpoint order is the project's)", got)
	}

	if api.ListenerSet != catalog.ListenerSetServe || strings.Join(api.RouteNamespaces, ",") != "api" {
		t.Errorf("api group = %+v, want served, admitting its own namespace", api)
	}

	var primary catalog.NamedGroup

	for _, g := range c.Groups("public", "dev") {
		if g.Name == "shop-primary" {
			primary = g
		}
	}

	if primary.Description != "The shop." || primary.Domains[0].ListenerNameOrDefault() != "shop" ||
		primary.Domains[0].SecretNameOrDefault() != "shop-tls" {
		t.Errorf("override not applied: %+v", primary)
	}

	// A project with no endpoint on a cluster gets no group there.
	if got := len(c.Groups("public", "prod")); got != 2 {
		t.Errorf("prod has %d groups, want console and shop", got)
	}
}

func TestGeneratedHostsJoinTheTunnelList(t *testing.T) {
	c := load(t, fixture)
	if err := c.WithProjects(projects); err != nil {
		t.Fatal(err)
	}

	hosts := strings.Join(c.TunnelHosts("dev"), ",")
	for _, want := range []string{"api.dev.example.com", "ssi.dev.example.com", "shop.dev.example.com"} {
		if !strings.Contains(hosts, want) {
			t.Errorf("tunnel hosts %s lack %s", hosts, want)
		}
	}
}

func TestWithProjectsRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		doc      string
		projects []catalog.Project
		want     string
	}{
		"a generated name meets a written one": {
			doc:  strings.Replace(fixture, "group: shop-primary", "group: console", 1),
			want: "a group of that name is written",
		},
		"an override for a project that left": {
			doc:      fixture,
			projects: projects[1:],
			want:     "no endpoint on this cluster",
		},
		"two groups on one host": {
			doc: fixture,
			projects: append([]catalog.Project{{Name: "dup", Endpoints: []catalog.Endpoint{
				{Environment: "dev", Hostname: "console.dev.example.com"},
			}}}, projects...),
			want: "claimed on dev",
		},
	} {
		t.Run(name, func(t *testing.T) {
			ps := tc.projects
			if ps == nil {
				ps = projects
			}

			err := load(t, tc.doc).WithProjects(ps)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestOverrideOnAnExposureThatLacksTheCluster(t *testing.T) {
	doc := strings.Replace(fixture, "        dev:\n          shop:", "        nowhere:\n          shop:", 1)

	err := load(t, doc).WithProjects(projects)
	if err == nil || !strings.Contains(err.Error(), "does not run on that cluster") {
		t.Fatalf("err = %v", err)
	}
}

func TestACatalogWithoutGenerationIsValidatedByLoad(t *testing.T) {
	_, err := catalog.Load(fstest.MapFS{catalog.FileName: {Data: []byte(`
version: 1
exposures:
  public:
    class: edge
    arrival: cloudflare-tunnel
    clusters:
      dev:
        groups: {}
`)}})
	if err == nil || !strings.Contains(err.Error(), "admits no listener") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownKeysAreRefused(t *testing.T) {
	_, err := catalog.Load(fstest.MapFS{catalog.FileName: {Data: []byte("version: 1\nbogus: 1\nexposures: {}\n")}})
	if err == nil {
		t.Fatal("an unknown key loaded")
	}
}

func TestGrants(t *testing.T) {
	kinds := []catalog.RouteKind{{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute"}}

	one := catalog.NamespacesGrant([]string{"a"}, kinds)
	if one.AllowedNamespaces.Selector.MatchLabels[catalog.NamespaceNameLabel] != "a" || len(one.AllowedNamespaces.Selector.MatchExpressions) != 0 {
		t.Errorf("one namespace is a plain match: %+v", one)
	}

	many := catalog.NamespacesGrant([]string{"b", "a"}, kinds)
	expr := many.AllowedNamespaces.Selector.MatchExpressions
	if len(expr) != 1 || expr[0].Operator != "In" || strings.Join(expr[0].Values, ",") != "a,b" {
		t.Errorf("several namespaces are one sorted In expression: %+v", many)
	}

	if many.AllowedNamespaces.From != catalog.FromSelector {
		t.Errorf("from = %s", many.AllowedNamespaces.From)
	}
}
