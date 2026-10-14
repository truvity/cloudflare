package catalog_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/truvity/gateway/catalog"
)

func TestClientProxyDefaults(t *testing.T) {
	var none *catalog.ClientProxy

	if !none.ForwardsBearer() || none.PostureOrDefault() != catalog.PostureAuthenticated {
		t.Fatal("no proxy forwards the bearer and leaves authorization with the application")
	}

	off := false
	p := &catalog.ClientProxy{ForwardBearer: &off, Posture: catalog.PostureGroups}

	if p.ForwardsBearer() || p.PostureOrDefault() != catalog.PostureGroups {
		t.Fatal("the row says otherwise")
	}

	if !(&catalog.ClientProxy{}).ForwardsBearer() {
		t.Fatal("unset forwards")
	}
}

func TestClientProxyValidate(t *testing.T) {
	const where = "rows[web].proxy"

	ok := func() *catalog.ClientProxy { return &catalog.ClientProxy{AttachRouteName: "web"} }

	if err := ok().Validate(where, nil); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		edit func(*catalog.ClientProxy)
		want string
	}{
		"no route":             {func(p *catalog.ClientProxy) { p.AttachRouteName = "" }, "name the route this binds to with attach_route_name"},
		"a rule not a name":    {func(p *catalog.ClientProxy) { p.AttachRouteRule = "Static_Assets" }, "rows[web].proxy.attach_route_rule: \"Static_Assets\" is not a Gateway API rule name"},
		"unknown csrf":         {func(p *catalog.ClientProxy) { p.CSRF = "warn" }, `.csrf: "warn" is not "off", "shadow" or "enforce"`},
		"origins without csrf": {func(p *catalog.ClientProxy) { p.CSRFAdditionalOrigins = []string{"https://a.example.com"} }, "listed without csrf"},
		"unknown samesite":     {func(p *catalog.ClientProxy) { p.SameSite = "lax" }, `.same_site: "lax" is not Lax, Strict or None`},
		"allow under default":  {func(p *catalog.ClientProxy) { p.Allow = []string{"staff"} }, "`allow` would be read by nothing"},
		"groups with no allow": {func(p *catalog.ClientProxy) { p.Posture = catalog.PostureGroups }, "admits nobody"},
		"unknown posture":      {func(p *catalog.ClientProxy) { p.Posture = "open" }, `posture "open" is neither`},
	} {
		t.Run(name, func(t *testing.T) {
			p := ok()
			tc.edit(p)

			err := p.Validate(where, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}

	t.Run("enforce with origins is a policy", func(t *testing.T) {
		p := ok()
		p.CSRF = catalog.CSRFEnforce
		p.CSRFAdditionalOrigins = []string{"https://a.example.com"}
		p.SameSite = "Strict"

		if err := p.Validate(where, nil); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("the estate vocabulary is the caller's", func(t *testing.T) {
		p := ok()
		p.Posture = catalog.PostureGroups
		p.Allow = []string{"nobody-knows"}

		err := p.Validate(where, func([]string) error { return errors.New("unknown group") })
		if err == nil || err.Error() != "unknown group" {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("rule names", func(t *testing.T) {
		for rule, valid := range map[string]bool{"app": true, "static": true, "a.b-c": true, "-a": false, "a-": false, "A": false, "a..b": false, "": false} {
			if catalog.IsRouteRuleName(rule) != valid {
				t.Errorf("%q: want %v", rule, valid)
			}
		}
	})
}
