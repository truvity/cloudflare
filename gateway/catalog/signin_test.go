package catalog_test

import (
	"reflect"
	"testing"

	"github.com/truvity/gateway/catalog"
)

func TestSignInPolicy(t *testing.T) {
	in := catalog.SignIn{ClientID: "shop", Hostname: "shop.example.com", Namespace: "shop", SecretName: "shop-client", PathPrefix: "/oauth2"}

	t.Run("the defaults", func(t *testing.T) {
		p := &catalog.ClientProxy{AttachRouteName: "shop"}

		got := p.SignInPolicy(in)
		want := catalog.SignInPolicy{
			Type: "oidc", Namespace: "shop",
			TargetRefs: []catalog.PolicyTargetRef{{Kind: "HTTPRoute", Name: "shop"}},
			OIDC: catalog.SignInOIDC{
				ClientID: "shop", ClientSecret: catalog.SecretRef{Name: "shop-client"},
				RedirectURL: "https://shop.example.com/oauth2/callback", LogoutPath: "/oauth2/logout",
				ForwardAccessToken: true, IDToken: catalog.IDTokenAudiences{Audiences: []string{"shop"}},
			},
			Authorization: catalog.SignInAuthorization{Posture: catalog.PostureAuthenticated, Groups: []string{}},
			CSRF:          catalog.PolicyCSRF{Mode: catalog.CSRFOff, AdditionalOrigins: []string{}},
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v\nwant %+v", got, want)
		}
	})

	t.Run("a named rule, groups, no bearer, csrf", func(t *testing.T) {
		off := false
		p := &catalog.ClientProxy{
			AttachRouteName: "shop", AttachRouteRule: "app", Posture: catalog.PostureGroups, Allow: []string{"shop:admin"},
			ForwardBearer: &off, CSRF: catalog.CSRFShadow, CSRFAdditionalOrigins: []string{"https://other.example.com"}, SameSite: "Strict",
		}

		got := p.SignInPolicy(in)
		if got.TargetRefs[0].SectionName != "app" || got.OIDC.ForwardAccessToken || got.OIDC.CookieSameSite != "Strict" {
			t.Fatalf("binding and cookie: %+v", got)
		}

		if got.Authorization.Posture != catalog.PostureGroups || !reflect.DeepEqual(got.Authorization.Groups, []string{"shop:admin"}) {
			t.Fatalf("authorization: %+v", got.Authorization)
		}

		if got.CSRF.Mode != catalog.CSRFShadow || got.CSRF.AdditionalOrigins[0] != "https://other.example.com" {
			t.Fatalf("csrf: %+v", got.CSRF)
		}
	})

	t.Run("csrf off keeps no origins", func(t *testing.T) {
		p := &catalog.ClientProxy{AttachRouteName: "shop", CSRF: catalog.CSRFOff, CSRFAdditionalOrigins: []string{"https://x.example.com"}}
		if got := p.SignInPolicy(in).CSRF; !reflect.DeepEqual(got, catalog.PolicyCSRF{Mode: catalog.CSRFOff, AdditionalOrigins: []string{}}) {
			t.Fatalf("csrf: %+v", got)
		}
	})
}
