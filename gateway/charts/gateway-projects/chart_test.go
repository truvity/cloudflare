// Copyright 2026 Truvity B.V.. All rights reserved.
// SPDX-License-Identifier: MIT

// Package chart_test holds gateway-projects to its one promise: a section
// renders exactly the objects its own chart renders for the same values. The
// templates are carried over by hack/sync-gateway-projects.sh, so this is the
// check that the carry is faithful.
package chart_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func objects(t *testing.T, chart, values string) map[string]map[string]any {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), "helm", "template", "x", chart, "--namespace", "ns", "-f", "-")
	cmd.Stdin = strings.NewReader(values)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template %s failed: %v\n%s", chart, err, out)
	}

	objs := map[string]map[string]any{}

	for _, d := range strings.Split(string(out), "\n---") {
		var m map[string]any
		if yaml.Unmarshal([]byte(d), &m) != nil || len(m) == 0 {
			continue
		}

		meta := m["metadata"].(map[string]any)
		ns, _ := meta["namespace"].(string)
		objs[m["kind"].(string)+"/"+ns+"/"+meta["name"].(string)] = m
	}

	return objs
}

func TestSectionsRenderWhatTheirChartsRender(t *testing.T) {
	for section, chart := range map[string]string{"groups": "gateway-groups", "policies": "gateway-policies"} {
		cases, err := filepath.Glob("../../tests/cases/" + chart + "/*/values.yaml")
		if err != nil || len(cases) == 0 {
			t.Fatalf("no cases for %s: %v", chart, err)
		}

		for _, path := range cases {
			t.Run(chart+"/"+filepath.Base(filepath.Dir(path)), func(t *testing.T) {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}

				var values map[string]any
				if err := yaml.Unmarshal(raw, &values); err != nil {
					t.Fatal(err)
				}

				wrapped := map[string]any{section: values}
				if section == "groups" {
					// The policies chart's TLS floor is on by default: not what this case compares.
					wrapped["policies"] = map[string]any{"tlsBaseline": map[string]any{"enabled": false}}
				}

				out, err := yaml.Marshal(wrapped)
				if err != nil {
					t.Fatal(err)
				}

				if want, got := objects(t, "../"+chart, string(raw)), objects(t, ".", string(out)); !reflect.DeepEqual(want, got) {
					t.Errorf("%s renders differently through gateway-projects", chart)
				}
			})
		}
	}
}
