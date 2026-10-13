package presettoken

import (
	"strconv"
	"strings"
)

// parseVersion reads MAJOR.MINOR.PATCH, with an optional leading "v"; the
// bool is false for anything else, and for a pre-release.
func parseVersion(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	core, pre, _ := strings.Cut(v, "-")

	var out [3]int

	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return out, false
	}

	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}

		out[i] = n
	}

	return out, pre == ""
}

// versionAtLeast compares MAJOR.MINOR.PATCH; a pre-release is older than its
// release and an unparsable have is older than anything.
func versionAtLeast(have, want string) bool {
	h, hRelease := parseVersion(have)
	w, _ := parseVersion(want)

	if h == [3]int{} && !hRelease {
		return false
	}

	for i := range h {
		if h[i] != w[i] {
			return h[i] > w[i]
		}
	}

	return hRelease
}
