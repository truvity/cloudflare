package catalog_test

import (
	"strings"
	"testing"

	"github.com/truvity/gateway/catalog"
)

const groupsLabel = "example.test/route-grant-business"

func groupsCatalog() *catalog.Config {
	on := catalog.ListenerSetServe

	return &catalog.Config{
		Version: catalog.Version,
		Exposures: map[string]catalog.Exposure{
			"public": {
				Class:   "edge",
				Arrival: catalog.ArrivalCloudflareTunnel,
				Clusters: map[string]catalog.Cluster{"dev": {Groups: map[string]catalog.Group{
					"console": {ListenerSet: on, Domains: []catalog.Domain{{Host: "console.dev.example.com"}}, RouteNamespaces: []string{"console-system"}},
					"shop":    {ListenerSet: on, Domains: []catalog.Domain{{Host: "shop.dev.example.com"}}, RouteNamespaces: []string{"shop"}},
					"shared": {ListenerSet: on, Domains: []catalog.Domain{{Host: "*.dev.example.com"}},
						RouteNamespaces: []string{"shop", "api"}},
					"duo": {ListenerSet: on, Domains: []catalog.Domain{{Host: "duo.dev.example.com"}},
						RouteNamespaces: []string{"shop", "api"}},
					"off": {Domains: []catalog.Domain{{Host: "off.dev.example.com"}}, RouteNamespaces: []string{"shop"}},
				}}},
			},
			"private": {
				Class:   "edge",
				Arrival: catalog.ArrivalPrivateClusterIP,
				Clusters: map[string]catalog.Cluster{"dev": {Groups: map[string]catalog.Group{
					"admin": {ListenerSet: on, Domains: []catalog.Domain{{Host: "admin.dev.example.private"}}, RouteNamespaces: []string{"shop"}},
				}}},
			},
		},
	}
}

func groupsInput() catalog.DeriveInput {
	return catalog.DeriveInput{
		Cluster:    "dev",
		OriginZone: "dev.example.com",
		Projects: []catalog.Project{
			{Name: "shop", ParentRefsSince: "1.0.0"},
			{Name: "api", ParentRefsSince: "2.0.0"},
		},
		PlatformConsumers:    map[string]string{"console": "console-system"},
		BusinessGrantLabel:   groupsLabel,
		ListenerSetNamespace: "gw-system",
		ReservedExposure:     "internal",
		PrivateParent:        "private-entry",
		PrivateCertificate:   &catalog.GroupCertificate{Issuer: "private-ca", Duration: "720h", RenewBefore: "240h", KeyAlgorithm: "ECDSA", KeySize: 384},
	}
}

func group(t *testing.T, got *catalog.GroupsValue, name string) catalog.GroupValue {
	t.Helper()

	for _, g := range got.Groups {
		if g.Name == name {
			return g
		}
	}

	t.Fatalf("no group %s", name)

	return catalog.GroupValue{}
}

func TestDeriveGroups(t *testing.T) {
	c := groupsCatalog()
	in := groupsInput()
	got, err := c.DeriveGroups(in)
	if err != nil {
		t.Fatal(err)
	}

	// One derived exposure: the private one is the caller's own Gateway.
	if len(got.Exposures) != 1 || got.Exposures[0] != (catalog.ExposureValue{
		Name: "public", Class: "edge",
		HealthHostname: "gateway-health-public.dev.example.com", HealthSecretName: "gateway-health-public-tls",
	}) {
		t.Fatalf("exposures: %+v", got.Exposures)
	}

	if len(got.Groups) != 5 {
		t.Fatalf("the listener_set groups only: %+v", got.Groups)
	}

	// A platform group admits its one namespace by name.
	console := group(t, got, "console")
	if console.Parent != "public" || console.AllowedRoutes.AllowedNamespaces.Selector.MatchLabels[catalog.NamespaceNameLabel] != "console-system" {
		t.Fatalf("console: %+v", console)
	}

	// Names are resolved, not left to the chart.
	if d := console.Domains[0]; d.ListenerName != "console-dev-example-com" || d.SecretName != "console-dev-example-com-tls" {
		t.Fatalf("names: %+v", d)
	}

	// An exact-host business group admits its own namespace by name.
	shop := group(t, got, "shop")
	if shop.AllowedRoutes.AllowedNamespaces.Selector.MatchLabels[catalog.NamespaceNameLabel] != "shop" {
		t.Fatalf("shop: %+v", shop.AllowedRoutes)
	}

	// Several namespaces: an In expression over exactly those.
	duo := group(t, got, "duo").AllowedRoutes.AllowedNamespaces.Selector.MatchExpressions
	if len(duo) != 1 || strings.Join(duo[0].Values, ",") != "api,shop" || duo[0].Operator != "In" {
		t.Fatalf("duo: %+v", duo)
	}

	// A business WILDCARD admits by the coarse label: per-install hosts
	// land in namespaces the catalog does not list.
	shared := group(t, got, "shared").AllowedRoutes
	if shared.AllowedNamespaces.Selector.MatchLabels[groupsLabel] != "true" || len(shared.AllowedNamespaces.Selector.MatchLabels) != 1 {
		t.Fatalf("shared: %+v", shared)
	}

	if shared.RouteKinds[0] != (catalog.RouteKind{Group: "gateway.networking.k8s.io", Kind: "HTTPRoute"}) {
		t.Fatalf("kinds: %+v", shared.RouteKinds)
	}

	// A private group naming one project namespace admits it by name, and
	// takes the entry's Gateway and certificate policy.
	admin := group(t, got, "admin")
	if admin.Parent != "private-entry" || admin.Certificate == nil || admin.Certificate.Issuer != "private-ca" ||
		admin.AllowedRoutes.AllowedNamespaces.Selector.MatchLabels[catalog.NamespaceNameLabel] != "shop" {
		t.Fatalf("admin: %+v", admin)
	}

	if group(t, got, "shop").Certificate != nil {
		t.Fatal("a tunnel-served group takes the default certificate")
	}

	if got.Namespace != "gw-system" {
		t.Fatalf("namespace %q", got.Namespace)
	}
}

func TestDeriveGroupsNothingWithoutTheFlag(t *testing.T) {
	c := groupsCatalog()

	in := groupsInput()
	in.Cluster = "prod"

	got, err := c.DeriveGroups(in)
	if err != nil || got != nil {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestDeriveGroupsRefusals(t *testing.T) {
	serve := catalog.ListenerSetServe

	one := func(arrival, name string, namespaces ...string) *catalog.Config {
		return &catalog.Config{Version: catalog.Version, Exposures: map[string]catalog.Exposure{
			"public": {Class: "edge", Arrival: arrival, Clusters: map[string]catalog.Cluster{"dev": {Groups: map[string]catalog.Group{
				name: {ListenerSet: serve, Domains: []catalog.Domain{{Host: name + ".dev.example.com"}}, RouteNamespaces: namespaces},
			}}}},
		}}
	}

	noParentRefs := func(in *catalog.DeriveInput) {
		in.Projects = []catalog.Project{{Name: "shop"}}
	}

	for name, tc := range map[string]struct {
		catalog *catalog.Config
		edit    func(*catalog.DeriveInput)
		want    string
	}{
		"an exposure nothing derives": {one(catalog.ArrivalNLB, "shop", "shop"), nil, "only cloudflare-tunnel and private-clusterip exposures are derived"},
		"no origin zone":              {one(catalog.ArrivalCloudflareTunnel, "shop", "shop"), func(in *catalog.DeriveInput) { in.OriginZone = "" }, "no origin zone"},
		"a platform group nothing moves": {one(catalog.ArrivalCloudflareTunnel, "tools", "tools-system"), nil,
			`nothing moves a platform group named "tools"`},
		"a platform group in the wrong namespace": {one(catalog.ArrivalCloudflareTunnel, "console", "elsewhere"), nil, "live in namespace console-system alone"},
		"business and platform in one group":      {one(catalog.ArrivalCloudflareTunnel, "shop", "shop", "tools-system"), nil, "cannot share a group"},
		"a project whose chart ignores parentRefs": {one(catalog.ArrivalCloudflareTunnel, "shop", "shop"), noParentRefs,
			"project shop has no exposure_parent_refs_since"},
		"a private group with no entry": {one(catalog.ArrivalPrivateClusterIP, "shop", "shop"), func(in *catalog.DeriveInput) { in.PrivateCertificate = nil },
			"no private entry"},
		"the reserved exposure": {&catalog.Config{Version: catalog.Version, Exposures: map[string]catalog.Exposure{
			"internal": {Class: "edge", Arrival: catalog.ArrivalCloudflareTunnel, Clusters: map[string]catalog.Cluster{"dev": {Groups: map[string]catalog.Group{
				"shop": {ListenerSet: serve, Domains: []catalog.Domain{{Host: "shop.dev.example.com"}}, RouteNamespaces: []string{"shop"}},
			}}}},
		}}, nil, "would replace it"},
	} {
		t.Run(name, func(t *testing.T) {
			in := groupsInput()
			if tc.edit != nil {
				tc.edit(&in)
			}

			_, err := tc.catalog.DeriveGroups(in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}

	t.Run("one ListenerSet name on two exposures", func(t *testing.T) {
		c := groupsCatalog()
		c.Exposures["private"].Clusters["dev"].Groups["shop"] = catalog.Group{
			ListenerSet: serve, Domains: []catalog.Domain{{Host: "shop.dev.example.private"}}, RouteNamespaces: []string{"shop"},
		}

		_, err := c.DeriveGroups(groupsInput())
		if err == nil || !strings.Contains(err.Error(), "both would be ListenerSet gw-system/shop") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestListenerSetsFor(t *testing.T) {
	c := groupsCatalog()

	in := groupsInput()

	got, err := c.DeriveGroups(in)
	if err != nil {
		t.Fatal(err)
	}

	refs, err := got.ListenerSetsFor([]catalog.ProjectHost{
		{Project: "shop", Hostname: "shop.dev.example.com"},
		{Project: "api", Hostname: "api.elsewhere.example.com"},
	}, in.Projects)
	if err != nil {
		t.Fatal(err)
	}

	if refs["shop"] != (catalog.ListenerSetRef{Name: "shop", Namespace: "gw-system", ParentRefsSince: "1.0.0"}) {
		t.Fatalf("refs: %+v", refs)
	}

	if _, ok := refs["api"]; ok {
		t.Fatal("a project no group serves has no ListenerSet")
	}

	var nilGroups *catalog.GroupsValue
	if refs, err := nilGroups.ListenerSetsFor(nil, nil); refs != nil || err != nil {
		t.Fatal("no groups, nothing to point at")
	}

	t.Run("a surface on another group", func(t *testing.T) {
		_, err := got.ListenerSetsFor([]catalog.ProjectHost{
			{Project: "shop", Hostname: "shop.dev.example.com", Surfaces: []string{"duo.dev.example.com"}},
		}, in.Projects)
		if err == nil || !strings.Contains(err.Error(), "from different groups") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("a project whose chart ignores parentRefs", func(t *testing.T) {
		_, err := got.ListenerSetsFor([]catalog.ProjectHost{{Project: "shop", Hostname: "shop.dev.example.com"}},
			[]catalog.Project{{Name: "shop"}})
		if err == nil || !strings.Contains(err.Error(), "no exposure_parent_refs_since") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestWithProjectsRefusesAnEndpointThatIsNotAName(t *testing.T) {
	for _, host := range []string{"Shop.dev.example.com", "shop", "*.dev.example.com", "10.0.0.1", "shop.dev.example.com."} {
		c := load(t, fixture)

		err := c.WithProjects([]catalog.Project{{Name: "shop", Endpoints: []catalog.Endpoint{{Environment: "dev", Hostname: host}}}})
		if err == nil || !strings.Contains(err.Error(), "not a lowercase DNS name") {
			t.Fatalf("%q: got %v", host, err)
		}
	}
}
