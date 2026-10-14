package catalog

import "slices"

const (
	// NamespaceNameLabel is set by the API server on every namespace and
	// cannot be changed or removed, which is what makes it a grant with
	// nothing to roll out first.
	NamespaceNameLabel = "kubernetes.io/metadata.name"

	// FromSelector is Gateway API's allowedRoutes.namespaces.from value for
	// a grant by label.
	FromSelector = "Selector"
)

type (
	// AllowedNamespaces is Gateway API's allowedRoutes.namespaces shape, as
	// a ListenerSet's grant is written; LabelSelector, LabelExpression and
	// RouteKind are the other allowedRoutes shapes.
	AllowedNamespaces struct {
		From     string        `yaml:"from"`
		Selector LabelSelector `yaml:"selector,omitempty"`
	}

	// LabelSelector selects namespaces by label.
	LabelSelector struct {
		MatchLabels      map[string]string `yaml:"matchLabels,omitempty"`
		MatchExpressions []LabelExpression `yaml:"matchExpressions,omitempty"`
	}

	// LabelExpression is one matchExpressions entry of a LabelSelector.
	LabelExpression struct {
		Key      string   `yaml:"key"`
		Operator string   `yaml:"operator"`
		Values   []string `yaml:"values,omitempty"`
	}

	// RouteKind is one kind of route a grant admits.
	RouteKind struct {
		Group string `yaml:"group"`
		Kind  string `yaml:"kind"`
	}

	// AllowedRoutes is one listener's grant: which namespaces may attach
	// which kinds of route.
	AllowedRoutes struct {
		AllowedNamespaces AllowedNamespaces
		RouteKinds        []RouteKind
	}
)

// NamespacesGrant admits the named namespaces, and no others, by the name
// label the API server sets on each. One namespace is a plain match; several
// are an In expression over exactly the namespaces listed.
//
// The name label is immutable and unique, so a grant by it needs no label
// written first and cannot be widened by anyone who can label a namespace.
func NamespacesGrant(namespaces []string, kinds []RouteKind) AllowedRoutes {
	if len(namespaces) == 1 {
		return NamespaceGrant(namespaces[0], kinds)
	}

	return AllowedRoutes{
		AllowedNamespaces: AllowedNamespaces{
			From: FromSelector,
			Selector: LabelSelector{MatchExpressions: []LabelExpression{{
				Key:      NamespaceNameLabel,
				Operator: "In",
				Values:   slices.Sorted(slices.Values(namespaces)),
			}}},
		},
		RouteKinds: slices.Clone(kinds),
	}
}

// NamespaceGrant admits one namespace by the name label.
func NamespaceGrant(namespace string, kinds []RouteKind) AllowedRoutes {
	return AllowedRoutes{
		AllowedNamespaces: AllowedNamespaces{
			From:     FromSelector,
			Selector: LabelSelector{MatchLabels: map[string]string{NamespaceNameLabel: namespace}},
		},
		RouteKinds: slices.Clone(kinds),
	}
}
