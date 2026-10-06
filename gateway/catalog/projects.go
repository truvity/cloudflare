package catalog

import "fmt"

// Project is the part of a project the generation reads: its name, which is
// also the namespace its routes live in, and the exact hostnames it is
// served on. A hostname is served on the cluster named by its Environment.
type Project struct {
	Name      string
	Endpoints []Endpoint
	// ParentRefsSince is the first release of the project's chart that
	// takes its routes' parents from a list the platform writes. Empty
	// means no release does, so the project's routes cannot move onto a
	// ListenerSet.
	ParentRefsSince string
}

// Endpoint is one exact hostname of a project, in the order the project
// lists it.
type Endpoint struct {
	Environment string
	Hostname    string
}

type (
	// ProjectGroups configures the generation on one exposure. Absent, the
	// exposure's groups are exactly the ones written in the catalog.
	//
	// With it, every project that has an endpoint on a cluster this
	// exposure runs on gets one group there: named after the project,
	// answering to the project's hostnames on that cluster, admitting the
	// project's own namespace, served from its own ListenerSet. Adding a
	// project endpoint is the whole change for a new listener.
	//
	// Overrides is what the generation cannot derive: a group name that
	// keeps a live object, listener and Secret names that do the same, the
	// text a console shows.
	ProjectGroups struct {
		// Overrides is keyed by cluster, then by project.
		Overrides map[string]map[string]ProjectOverride `yaml:"overrides,omitempty"`
	}

	// ProjectOverride adjusts one project's generated group on one cluster.
	ProjectOverride struct {
		// Group names the group where the project's own name is taken (by
		// a wildcard group of another claim) or must stay what it was.
		Group       string `yaml:"group,omitempty"`
		Description string `yaml:"description,omitempty"`
		// Names keeps the object names of a listener that is already
		// live, by hostname: see Domain.
		Names map[string]DomainNames `yaml:"names,omitempty"`
	}

	// DomainNames are the object names a hostname's listener and Secret
	// keep.
	DomainNames struct {
		ListenerName string `yaml:"listener_name,omitempty"`
		SecretName   string `yaml:"secret_name,omitempty"`
	}
)

func (p *ProjectGroups) validate(exposure string, e Exposure) error {
	if p == nil {
		return nil
	}

	for cluster, projects := range p.Overrides {
		if _, ok := e.Clusters[cluster]; !ok {
			return fmt.Errorf("cfg/gateways: exposures[%s].project_groups.overrides[%s]: the exposure does not run on that cluster",
				exposure, cluster)
		}

		for project, override := range projects {
			if override.Group == "" && override.Description == "" && len(override.Names) == 0 {
				return fmt.Errorf("cfg/gateways: exposures[%s].project_groups.overrides[%s][%s] overrides nothing",
					exposure, cluster, project)
			}

			if override.Group != "" && !dnsLabel.MatchString(override.Group) {
				return fmt.Errorf("cfg/gateways: exposures[%s].project_groups.overrides[%s][%s].group: %q is not a DNS label",
					exposure, cluster, project, override.Group)
			}
		}
	}

	return nil
}

// WithProjects adds the generated groups to the catalog and validates the
// result. It must be called once, before anything reads the groups, so
// that every reader (listeners, tunnel rules, DNS, status) sees the same
// rows. A catalog with no project_groups section is returned unchanged.
//
// A generated group that meets a written group of the same name is an
// error, not a merge: the generation never silently replaces a claim. The
// way out is the override's Group name.
func (c *Config) WithProjects(projects []Project) error {
	for _, project := range projects {
		for _, endpoint := range project.Endpoints {
			if !IsDNSClaim(endpoint.Hostname) {
				return fmt.Errorf("cfg/gateways: project %s: endpoint hostname %q is not a lowercase DNS name a record can be written for",
					project.Name, endpoint.Hostname)
			}
		}
	}

	for _, exposureName := range sortedKeys(c.Exposures) {
		exposure := c.Exposures[exposureName]
		if exposure.ProjectGroups == nil {
			continue
		}

		if err := exposure.ProjectGroups.validate(exposureName, exposure); err != nil {
			return err
		}

		used := map[string]bool{}

		for _, cluster := range sortedKeys(exposure.Clusters) {
			clusterRow := exposure.Clusters[cluster]
			if clusterRow.Groups == nil {
				clusterRow.Groups = map[string]Group{}
			}

			for _, project := range projects {
				var domains []Domain

				override := exposure.ProjectGroups.Overrides[cluster][project.Name]

				for _, endpoint := range project.Endpoints {
					if endpoint.Environment != cluster {
						continue
					}

					domain := Domain{Host: endpoint.Hostname}
					if names, ok := override.Names[endpoint.Hostname]; ok {
						domain.ListenerName = names.ListenerName
						domain.SecretName = names.SecretName
					}

					domains = append(domains, domain)
				}

				if len(domains) == 0 {
					continue
				}

				used[cluster+"|"+project.Name] = true

				name := project.Name
				if override.Group != "" {
					name = override.Group
				}

				if _, taken := clusterRow.Groups[name]; taken {
					return fmt.Errorf(
						"cfg/gateways: exposures[%s].clusters[%s]: the generated group for project %s is named %q, and a group of that name is written in the catalog; "+
							"rename it with project_groups.overrides[%s][%s].group",
						exposureName, cluster, project.Name, name, cluster, project.Name)
				}

				clusterRow.Groups[name] = Group{
					Description:     override.Description,
					Domains:         domains,
					RouteNamespaces: []string{project.Name},
					ListenerSet:     ListenerSetServe,
				}
			}

			exposure.Clusters[cluster] = clusterRow
		}

		// An override for a project with nothing to serve on that cluster
		// is a leftover of a move, and would read as a live claim.
		for cluster, overrides := range exposure.ProjectGroups.Overrides {
			for project := range overrides {
				if !used[cluster+"|"+project] {
					return fmt.Errorf("cfg/gateways: exposures[%s].project_groups.overrides[%s][%s]: the project has no endpoint on this cluster",
						exposureName, cluster, project)
				}
			}
		}
	}

	return c.Validate()
}
