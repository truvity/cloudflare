package config

import (
	"fmt"
	"sort"
)

// ValidateForeignHosts holds every environment's foreign hosts to a zone this
// registry declares: a foreign host is a legacy name the estate adopts, and
// the estate can only adopt a name whose zone it manages. The zone is the
// name's longest declared zone suffix (ZoneOf), the same rule a tunnel host
// resolves by.
//
// foreign maps an environment (a cluster) to its foreign hosts; the estate
// reads them from its project list. Checking the rest of a foreign host
// (an exact name, outside the estate's own zones, listed once) is the project
// list's.
func (c *Config) ValidateForeignHosts(foreign map[string][]string) error {
	if foreign == nil {
		return fmt.Errorf("%s: the foreign hosts are required to cross-check them", FileName)
	}

	envs := make([]string, 0, len(foreign))
	for env := range foreign {
		envs = append(envs, env)
	}

	sort.Strings(envs)

	for _, env := range envs {
		for _, host := range foreign[env] {
			if c.ZoneOf(host) == "" {
				return fmt.Errorf("%s: environment %s foreign host %q lies in no zone declared here", FileName, env, host)
			}
		}
	}

	return nil
}
