package catalog

import (
	"net"
	"strings"
)

// IsDNSLabel reports whether label is one lowercase RFC 1123 label.
func IsDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}

	for _, char := range label {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}

	return true
}

// IsDNSName reports whether name is a lowercase, absolute-less DNS name of
// at least two labels, and not an IP address.
func IsDNSName(name string) bool {
	if name == "" || len(name) > 253 || name != strings.ToLower(name) || net.ParseIP(name) != nil || strings.HasSuffix(name, ".") {
		return false
	}

	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}

	for _, label := range labels {
		if !IsDNSLabel(label) {
			return false
		}
	}

	return true
}

// IsDNSClaim reports whether name is a DNS name a record can be written
// for: IsDNSName, and no wildcard.
func IsDNSClaim(name string) bool {
	return !strings.Contains(name, "*") && IsDNSName(name)
}

// IsNameUnderDomain reports whether name is a proper subdomain of domain.
func IsNameUnderDomain(name, domain string) bool {
	name = strings.ToLower(name)
	domain = strings.ToLower(domain)

	return name != domain && strings.HasSuffix(name, "."+domain)
}
