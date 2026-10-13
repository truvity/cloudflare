package catalog

// SignIn is what the gateway-policies chart's sign-in SecurityPolicy needs
// from a console's row besides its ClientProxy: the client at the issuer,
// where the console answers, and the path the gateway owns there.
type SignIn struct {
	// ClientID is the client at the issuer, and the audience an ID token is
	// minted for.
	ClientID string
	// Hostname is the console's host, where the issuer sends the browser
	// back.
	Hostname string
	// Namespace is the namespace of the route the policy binds to.
	Namespace string
	// SecretName is the Secret, in Namespace, that holds the client's
	// secret.
	SecretName string
	// PathPrefix is the path the gateway owns on Hostname: the callback and
	// the logout live under it. The redirect registered at the issuer must
	// be this prefix plus /callback, so both are derived from one value.
	PathPrefix string
}

type (
	// SignInPolicy is one entry of the gateway-policies chart's
	// securityPolicies: the gateway signing people in for one console's
	// route. The issuer, its endpoints and how the data plane reaches it
	// are the release's `defaults.oidc`, which every entry inherits.
	SignInPolicy struct {
		Type          string              `yaml:"type" json:"type"`
		Namespace     string              `yaml:"namespace" json:"namespace"`
		TargetRefs    []PolicyTargetRef   `yaml:"targetRefs" json:"targetRefs"`
		OIDC          SignInOIDC          `yaml:"oidc" json:"oidc"`
		Authorization SignInAuthorization `yaml:"authorization" json:"authorization"`
		CSRF          PolicyCSRF          `yaml:"csrf" json:"csrf"`
	}

	// PolicyTargetRef is what a SecurityPolicy binds to: a route, or one
	// named rule of it.
	PolicyTargetRef struct {
		Kind        string `yaml:"kind" json:"kind"`
		Name        string `yaml:"name" json:"name"`
		SectionName string `yaml:"sectionName,omitempty" json:"sectionName,omitempty"`
	}

	// SignInOIDC is the client side of the sign-in.
	SignInOIDC struct {
		ClientID           string           `yaml:"clientID" json:"clientID"`
		ClientSecret       SecretRef        `yaml:"clientSecret" json:"clientSecret"`
		RedirectURL        string           `yaml:"redirectURL" json:"redirectURL"`
		LogoutPath         string           `yaml:"logoutPath" json:"logoutPath"`
		CookieSameSite     string           `yaml:"cookieSameSite" json:"cookieSameSite"`
		ForwardAccessToken bool             `yaml:"forwardAccessToken" json:"forwardAccessToken"`
		IDToken            IDTokenAudiences `yaml:"idToken" json:"idToken"`
	}

	// SecretRef names a Secret in the policy's namespace.
	SecretRef struct {
		Name string `yaml:"name" json:"name"`
	}

	// IDTokenAudiences is the audiences an ID token must carry.
	IDTokenAudiences struct {
		Audiences []string `yaml:"audiences" json:"audiences"`
	}

	// SignInAuthorization is who passes once signed in.
	SignInAuthorization struct {
		Posture string   `yaml:"posture" json:"posture"`
		Groups  []string `yaml:"groups" json:"groups"`
	}

	// PolicyCSRF is a policy's Origin check.
	PolicyCSRF struct {
		Mode              string   `yaml:"mode" json:"mode"`
		AdditionalOrigins []string `yaml:"additionalOrigins" json:"additionalOrigins"`
	}
)

// SignInPolicy is the gateway-policies entry that signs people in for this
// proxy's route: bound to the route, or to its one named rule; the redirect
// and the logout under the client's own prefix; the posture, the bearer and
// the cookie defences of the row with their defaults. Every field is
// stated, so a chart release that moves a default cannot move a console.
func (p *ClientProxy) SignInPolicy(in SignIn) SignInPolicy {
	csrf := PolicyCSRF{Mode: CSRFOff, AdditionalOrigins: []string{}}
	if p.CSRF != "" && p.CSRF != CSRFOff {
		csrf.Mode = p.CSRF
		if p.CSRFAdditionalOrigins != nil {
			csrf.AdditionalOrigins = p.CSRFAdditionalOrigins
		}
	}

	allow := p.Allow
	if allow == nil {
		allow = []string{}
	}

	return SignInPolicy{
		Type:      "oidc",
		Namespace: in.Namespace,
		// The application's own route. Another SecurityPolicy on it is
		// resolved to the OLDER of the two, so this one waits, conflicted,
		// until that is gone.
		TargetRefs: []PolicyTargetRef{{Kind: "HTTPRoute", Name: p.AttachRouteName, SectionName: p.AttachRouteRule}},
		OIDC: SignInOIDC{
			ClientID:           in.ClientID,
			ClientSecret:       SecretRef{in.SecretName},
			RedirectURL:        "https://" + in.Hostname + in.PathPrefix + "/callback",
			LogoutPath:         in.PathPrefix + "/logout",
			CookieSameSite:     p.SameSite,
			ForwardAccessToken: p.ForwardsBearer(),
			IDToken:            IDTokenAudiences{[]string{in.ClientID}},
		},
		Authorization: SignInAuthorization{Posture: p.PostureOrDefault(), Groups: allow},
		CSRF:          csrf,
	}
}
