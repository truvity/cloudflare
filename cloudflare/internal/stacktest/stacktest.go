// Package stacktest records what a Pulumi program registers under the
// engine's mocks: every resource's type, name, parent, provider and inputs.
// It is test support for the stack entry points (zonestack, services,
// instancetunnel), whose goldens compare these records.
package stacktest

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Resource is one registered resource.
type Resource struct {
	Type string
	Name string
	// Parent is "<type>::<name>" of the parent, empty for a top-level resource.
	Parent string
	// Provider is the logical name of the provider, empty for none.
	Provider string
	Inputs   map[string]any
}

// Key is the resource's identity inside a stack: type and name.
func (r Resource) Key() string { return r.Type + "::" + r.Name }

// Recorder is the mocks plus the stack transformation that sees parents.
type Recorder struct {
	mu        sync.Mutex
	resources []Resource
	keys      map[pulumi.Resource]string
	parents   map[string]string
}

// Run executes program under a Recorder and returns it.
func Run(program func(ctx *pulumi.Context) error) (*Recorder, error) {
	r := &Recorder{keys: map[pulumi.Resource]string{}, parents: map[string]string{}}

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		if err := ctx.RegisterStackTransformation(r.observe); err != nil {
			return err
		}

		return program(ctx)
	}, pulumi.WithMocks("example", "stack", r))

	return r, err
}

func (r *Recorder) observe(ta *pulumi.ResourceTransformationArgs) *pulumi.ResourceTransformationResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := ta.Type + "::" + ta.Name
	r.keys[ta.Resource] = key

	if opts, err := pulumi.NewResourceOptions(ta.Opts...); err == nil && opts.Parent != nil {
		r.parents[key] = r.keys[opts.Parent]
	}

	return nil
}

// NewResource implements pulumi.MockResourceMonitor.
func (r *Recorder) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.resources = append(r.resources, Resource{
		Type: args.TypeToken, Name: args.Name, Provider: providerName(args.Provider),
		Inputs: args.Inputs.Mappable(),
	})

	return args.Name + "-id", args.Inputs.Copy(), nil
}

// Call implements pulumi.MockResourceMonitor.
func (r *Recorder) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	if args.Token == "cloudflare:index/getZeroTrustTunnelCloudflaredToken:getZeroTrustTunnelCloudflaredToken" {
		return resource.PropertyMap{"token": resource.NewStringProperty("tunnel-token")}, nil
	}

	return resource.PropertyMap{}, nil
}

// providerName is the logical name in a provider reference
// "urn:pulumi:<stack>::<project>::pulumi:providers:cloudflare::<name>::<id>".
func providerName(ref string) string {
	parts := strings.Split(ref, "::")
	if len(parts) < 4 {
		return ""
	}

	return parts[len(parts)-2]
}

// Resources is every registered resource with its parent, sorted by key.
func (r *Recorder) Resources() []Resource {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]Resource, len(r.resources))
	for i, res := range r.resources {
		res.Parent = r.parents[res.Key()]
		out[i] = res
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })

	return out
}

// ByKey is Resources indexed by Key.
func (r *Recorder) ByKey() map[string]Resource {
	out := map[string]Resource{}
	for _, res := range r.Resources() {
		out[res.Key()] = res
	}

	return out
}

// Render is the records as JSON: key to parent, provider and inputs (the
// bytes are stable).
func (r *Recorder) Render() ([]byte, error) {
	type entry struct {
		Parent   string         `json:"parent,omitempty"`
		Provider string         `json:"provider,omitempty"`
		Inputs   map[string]any `json:"inputs"`
	}

	out := map[string]entry{}
	for _, res := range r.Resources() {
		out[res.Key()] = entry{res.Parent, res.Provider, res.Inputs}
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}

	return append(b, '\n'), nil
}
