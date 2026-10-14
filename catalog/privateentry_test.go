package catalog_test

import (
	"strings"
	"testing"

	"github.com/truvity/gateway/catalog"
)

func testEntry(loadBalancer bool) *catalog.PrivateEntry {
	return catalog.NewPrivateEntry(catalog.PrivateEntryInput{
		Names: catalog.PrivateEntryNames{
			Namespace: "gw-system", Gateway: "private-entry", Listener: "https", Secret: "private-entry-tls",
			Issuer: "private-ca", TrafficPolicy: "private-entry-tls13", HealthPath: "/healthz",
			Service: "gateway-nlb", ClusterIPService: "gateway-ip",
		},
		Zone:              "dev.example.private",
		ClusterIP:         "172.21.0.20",
		LoadBalancer:      loadBalancer,
		Class:             "private",
		KeyAlgorithm:      "ECDSA",
		KeySize:           384,
		Duration:          "720h",
		RenewBefore:       "240h",
		MinimumTLSVersion: "TLS1.3",
	})
}

func TestPrivateEntryValues(t *testing.T) {
	entry := testEntry(false)

	if entry.Hostname != "gateway.dev.example.private" || entry.MinimumTLSVersion != "1.3" {
		t.Fatalf("%+v", entry)
	}

	var sb strings.Builder

	entry.WriteValues(&sb, catalog.PrivateEntryRender{ClusterName: "dev"})

	want := `privateEntry:
  namespace: gw-system
  gatewayName: private-entry
  listenerName: https
  class: private
  hostname: "gateway.dev.example.private"
  clusterIP: 172.21.0.20
  clusterIPService: gateway-ip
  tlsSecretName: private-entry-tls
  certificate:
    duration: "720h"
    renewBefore: "240h"
    privateKey:
      algorithm: ECDSA
      size: 384
    issuerRef:
      name: private-ca
  health:
    name: private-entry
    path: /healthz
    body: "dev private ingress ok\n"
  clientTrafficPolicy:
    name: private-entry-tls13
    tls:
      minVersion: "1.3"
      maxVersion: "1.3"
`
	if sb.String() != want {
		t.Fatalf("got:\n%s", sb.String())
	}

	// The load balancer is a block of its own, and an unpinned entry states
	// no address.
	sb.Reset()

	lb := testEntry(true)
	lb.ClusterIP = ""
	lb.WriteValues(&sb, catalog.PrivateEntryRender{ClusterName: "dev", SourceRanges: []string{"10.0.0.0/8", "100.64.0.0/10"}})

	got := sb.String()
	for _, line := range []string{
		"  service:\n    name: gateway-nlb\n    annotations:\n",
		"      service.beta.kubernetes.io/aws-load-balancer-scheme: internal\n",
		"    loadBalancerSourceRanges:\n      - 10.0.0.0/8\n      - 100.64.0.0/10\n",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing %q in\n%s", line, got)
		}
	}

	if strings.Contains(got, "clusterIP") || strings.Contains(got, "healthcheck-interval") {
		t.Errorf("unpinned and slow-health entry states neither:\n%s", got)
	}

	sb.Reset()
	lb.WriteValues(&sb, catalog.PrivateEntryRender{ClusterName: "dev", FastHealthCheck: true})

	if !strings.Contains(sb.String(), `healthcheck-interval: "5"`) || !strings.Contains(sb.String(), `unhealthy-threshold: "2"`) {
		t.Errorf("fast health check:\n%s", sb.String())
	}
}

func TestPrivateEntryGroupCertificate(t *testing.T) {
	got := testEntry(false).GroupCertificate()

	if *got != (catalog.GroupCertificate{Issuer: "private-ca", Duration: "720h", RenewBefore: "240h", KeyAlgorithm: "ECDSA", KeySize: 384}) {
		t.Fatalf("%+v", got)
	}
}

func TestGroupCertificateValues(t *testing.T) {
	var sb strings.Builder

	catalog.GroupCertificate{Issuer: "origin-ca"}.WriteValues(&sb, "  ")

	if sb.String() != "  issuerRef:\n    name: origin-ca\n    kind: ClusterIssuer\n    group: cert-manager.io\n" {
		t.Fatalf("a policy states only what it holds:\n%s", sb.String())
	}

	sb.Reset()
	catalog.GroupCertificate{Issuer: "ca", Duration: "1h", RenewBefore: "10m", KeyAlgorithm: "ECDSA", KeySize: 384}.WriteValues(&sb, "")

	if !strings.Contains(sb.String(), "duration: \"1h\"\nrenewBefore: \"10m\"\nprivateKey:\n  algorithm: ECDSA\n  size: 384\n  rotationPolicy: Always\n") {
		t.Fatalf("\n%s", sb.String())
	}
}

func TestGroupCertificateChartValues(t *testing.T) {
	var sb strings.Builder

	c := catalog.GroupCertificate{Issuer: "ca", Duration: "1h", RenewBefore: "10m", KeyAlgorithm: "ECDSA", KeySize: 384}
	c.WriteChartValues(&sb, "")

	if sb.String() != "duration: \"1h\"\nrenewBefore: \"10m\"\nprivateKey:\n  algorithm: ECDSA\n  size: 384\nissuerRef:\n  name: ca\n" {
		t.Fatalf("the charts default rotation, kind and group:\n%s", sb.String())
	}

	sb.Reset()
	c.WriteOverride(&sb, "")

	if strings.Contains(sb.String(), "rotationPolicy") || strings.Contains(sb.String(), "kind:") {
		t.Fatalf("an override states no default:\n%s", sb.String())
	}
}
