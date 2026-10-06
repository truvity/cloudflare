package catalog

import (
	"fmt"
	"strings"
)

// The private entry is the one Gateway every cluster keeps for its private
// names: a pinned ClusterIP in front of it, a health listener that keeps it
// alive, a TLS floor, and optionally an internal load balancer for the one
// client a ClusterIP cannot serve (another network that peering carries no
// service range for). This file derives its values; the caller owns the
// names, because each is the identity of a live object.

const (
	// RotationPolicyAlways is the certificate key rotation every entry and
	// group certificate states: a renewed leaf has a new key.
	rotationPolicyAlways = "Always"

	// ClusterIssuerKind and IssuerGroup are the issuer reference every
	// certificate here carries.
	clusterIssuerKind = "ClusterIssuer"
	issuerGroup       = "cert-manager.io"
)

type (
	// PrivateEntryNames are the object names of the entry. Each is the name
	// a live object has, so each is part of its identity: a change is a
	// delete and a create.
	PrivateEntryNames struct {
		Namespace     string
		Gateway       string
		Listener      string
		Secret        string
		Issuer        string
		TrafficPolicy string
		HealthPath    string
		// Service is the load balancer Service, and ClusterIPService the
		// ClusterIP Service beside it. A SECOND Service rather than a
		// clusterIP on the first: spec.clusterIP is immutable, so setting
		// one on a live LoadBalancer Service is a delete and a create of the
		// entry every private client uses.
		Service          string
		ClusterIPService string
	}

	// PrivateEntryInput is what the entry is derived from.
	PrivateEntryInput struct {
		Names PrivateEntryNames
		// Zone is the cluster's private zone; the entry answers as
		// gateway.<zone>.
		Zone string
		// ClusterIP is the pinned address the entry answers on. Empty
		// leaves it unpinned rather than guessed.
		ClusterIP string
		// LoadBalancer is whether the cluster keeps an internal load
		// balancer in front of the entry: true only where a private group
		// is cross_cluster (Config.PrivateEntryNeedsLoadBalancer).
		LoadBalancer bool
		// Class is the GatewayClass the entry is served by.
		Class string
		// KeyAlgorithm, KeySize, Duration and RenewBefore are the private
		// trust domain's leaf policy. The entry holds no opinion of its own
		// about the key: the issuer refuses a request of another size.
		KeyAlgorithm string
		KeySize      int
		Duration     string
		RenewBefore  string
		// MinimumTLSVersion is the policy's floor, "TLS1.3" or "1.3".
		MinimumTLSVersion string
	}

	// PrivateEntry is one cluster's shared private entry.
	PrivateEntry struct {
		Names             PrivateEntryNames
		Hostname          string
		ClusterIP         string
		LoadBalancer      bool
		Class             string
		KeyAlgorithm      string
		KeySize           int
		Duration          string
		RenewBefore       string
		MinimumTLSVersion string
	}

	// PrivateEntryRender is what the values of one cluster add to the
	// entry: facts of the cluster, not of the entry.
	PrivateEntryRender struct {
		// ClusterName is named in the health answer.
		ClusterName string
		// FastHealthCheck tightens the load balancer's health check: a
		// replaced proxy is a target again in about ten seconds and a gone
		// one is out in as many, rather than about thirty on the defaults.
		// For an entry that carries a passthrough with nothing else in
		// front of it. The timeout stays below the interval or the cloud
		// rejects it.
		FastHealthCheck bool
		// SourceRanges are the networks the load balancer admits.
		SourceRanges []string
	}
)

// NewPrivateEntry gives a cluster its shared private entry.
func NewPrivateEntry(in PrivateEntryInput) *PrivateEntry {
	return &PrivateEntry{
		Names:             in.Names,
		Hostname:          "gateway." + in.Zone,
		ClusterIP:         in.ClusterIP,
		LoadBalancer:      in.LoadBalancer,
		Class:             in.Class,
		KeyAlgorithm:      in.KeyAlgorithm,
		KeySize:           in.KeySize,
		Duration:          in.Duration,
		RenewBefore:       in.RenewBefore,
		MinimumTLSVersion: strings.TrimPrefix(in.MinimumTLSVersion, "TLS"),
	}
}

// GroupCertificate is the certificate policy a private group's listeners
// take: the entry's own, so the entry's listener and the groups beside it
// on the same Gateway can never be issued under different policies --
// including the key.
func (e *PrivateEntry) GroupCertificate() *GroupCertificate {
	return &GroupCertificate{
		Issuer:       e.Names.Issuer,
		Duration:     e.Duration,
		RenewBefore:  e.RenewBefore,
		KeyAlgorithm: e.KeyAlgorithm,
		KeySize:      e.KeySize,
	}
}

// WriteValues writes the entry as the `privateEntry` block the gateway-fleet
// values take, with the comment header the caller wrote above it. Every
// line is stated outright, so a reviewer of a render diff sees what changes.
func (e *PrivateEntry) WriteValues(sb *strings.Builder, r PrivateEntryRender) {
	sb.WriteString("privateEntry:\n")
	fmt.Fprintf(sb, "  namespace: %s\n", e.Names.Namespace)
	fmt.Fprintf(sb, "  gatewayName: %s\n", e.Names.Gateway)
	fmt.Fprintf(sb, "  listenerName: %s\n", e.Names.Listener)

	if e.Class != "" {
		fmt.Fprintf(sb, "  class: %s\n", e.Class)
	}

	fmt.Fprintf(sb, "  hostname: %q\n", e.Hostname)

	if e.ClusterIP != "" {
		fmt.Fprintf(sb, "  clusterIP: %s\n", e.ClusterIP)
		fmt.Fprintf(sb, "  clusterIPService: %s\n", e.Names.ClusterIPService)
	}

	fmt.Fprintf(sb, "  tlsSecretName: %s\n", e.Names.Secret)
	sb.WriteString("  certificate:\n")
	fmt.Fprintf(sb, "    duration: %q\n", e.Duration)
	fmt.Fprintf(sb, "    renewBefore: %q\n", e.RenewBefore)
	sb.WriteString("    privateKey:\n")
	fmt.Fprintf(sb, "      algorithm: %s\n", e.KeyAlgorithm)
	fmt.Fprintf(sb, "      size: %d\n", e.KeySize)
	fmt.Fprintf(sb, "      rotationPolicy: %s\n", rotationPolicyAlways)
	sb.WriteString("    issuerRef:\n")
	fmt.Fprintf(sb, "      name: %s\n", e.Names.Issuer)
	fmt.Fprintf(sb, "      kind: %s\n", clusterIssuerKind)
	fmt.Fprintf(sb, "      group: %s\n", issuerGroup)
	sb.WriteString("  health:\n")
	fmt.Fprintf(sb, "    name: %s\n", e.Names.Gateway)
	fmt.Fprintf(sb, "    path: %s\n", e.Names.HealthPath)
	fmt.Fprintf(sb, "    body: %q\n", r.ClusterName+" private ingress ok\n")
	sb.WriteString("  clientTrafficPolicy:\n")
	fmt.Fprintf(sb, "    name: %s\n", e.Names.TrafficPolicy)
	sb.WriteString("    tls:\n")
	fmt.Fprintf(sb, "      minVersion: %q\n", e.MinimumTLSVersion)
	fmt.Fprintf(sb, "      maxVersion: %q\n", e.MinimumTLSVersion)

	if !e.LoadBalancer {
		return
	}

	sb.WriteString("  service:\n")
	fmt.Fprintf(sb, "    name: %s\n", e.Names.Service)
	sb.WriteString("    annotations:\n")
	sb.WriteString("      service.beta.kubernetes.io/aws-load-balancer-scheme: internal\n")
	sb.WriteString("      service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: ip\n")
	sb.WriteString("      service.beta.kubernetes.io/aws-load-balancer-attributes: load_balancing.cross_zone.enabled=true\n")
	sb.WriteString("      service.beta.kubernetes.io/aws-load-balancer-target-group-attributes: deregistration_delay.timeout_seconds=30\n")
	sb.WriteString("      service.beta.kubernetes.io/aws-load-balancer-healthcheck-protocol: TCP\n")
	sb.WriteString("      service.beta.kubernetes.io/aws-load-balancer-healthcheck-port: traffic-port\n")

	if r.FastHealthCheck {
		sb.WriteString("      service.beta.kubernetes.io/aws-load-balancer-healthcheck-interval: \"5\"\n")
		sb.WriteString("      service.beta.kubernetes.io/aws-load-balancer-healthcheck-timeout: \"3\"\n")
		sb.WriteString("      service.beta.kubernetes.io/aws-load-balancer-healthcheck-healthy-threshold: \"2\"\n")
		sb.WriteString("      service.beta.kubernetes.io/aws-load-balancer-healthcheck-unhealthy-threshold: \"2\"\n")
	}

	sb.WriteString("    loadBalancerSourceRanges:\n")

	for _, source := range r.SourceRanges {
		fmt.Fprintf(sb, "      - %s\n", source)
	}
}

// WriteValues writes a certificate policy as the gateway-groups and
// gateway-fleet charts take it, at indent. Only what the policy states is
// written.
func (c GroupCertificate) WriteValues(sb *strings.Builder, indent string) {
	if c.Duration != "" {
		fmt.Fprintf(sb, "%sduration: %q\n", indent, c.Duration)
	}

	if c.RenewBefore != "" {
		fmt.Fprintf(sb, "%srenewBefore: %q\n", indent, c.RenewBefore)
	}

	if c.KeySize != 0 {
		fmt.Fprintf(sb, "%sprivateKey:\n", indent)
		fmt.Fprintf(sb, "%s  algorithm: %s\n", indent, c.KeyAlgorithm)
		fmt.Fprintf(sb, "%s  size: %d\n", indent, c.KeySize)
		fmt.Fprintf(sb, "%s  rotationPolicy: %s\n", indent, rotationPolicyAlways)
	}

	fmt.Fprintf(sb, "%sissuerRef:\n", indent)
	fmt.Fprintf(sb, "%s  name: %s\n", indent, c.Issuer)
	fmt.Fprintf(sb, "%s  kind: %s\n", indent, clusterIssuerKind)
	fmt.Fprintf(sb, "%s  group: %s\n", indent, issuerGroup)
}

// WriteOverride writes the certificate as a group's own `certificate`
// override: unlike the default policy, every field is stated, quoted as the
// chart's values are.
func (c GroupCertificate) WriteOverride(sb *strings.Builder, indent string) {
	fmt.Fprintf(sb, "%sduration: %q\n", indent, c.Duration)
	fmt.Fprintf(sb, "%srenewBefore: %q\n", indent, c.RenewBefore)
	fmt.Fprintf(sb, "%sprivateKey:\n", indent)
	fmt.Fprintf(sb, "%s  algorithm: %s\n", indent, c.KeyAlgorithm)
	fmt.Fprintf(sb, "%s  size: %d\n", indent, c.KeySize)
	fmt.Fprintf(sb, "%s  rotationPolicy: %s\n", indent, rotationPolicyAlways)
	fmt.Fprintf(sb, "%sissuerRef:\n", indent)
	fmt.Fprintf(sb, "%s  name: %s\n", indent, c.Issuer)
	fmt.Fprintf(sb, "%s  kind: %s\n", indent, clusterIssuerKind)
	fmt.Fprintf(sb, "%s  group: %s\n", indent, issuerGroup)
}
