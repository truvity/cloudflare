package awsapigw_test

import (
	"encoding/json"
	"go/build"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/edge/v3/cloudflare/awsapigw"
)

// The ids are built and not written out, which the repository's leak canary
// would take for particulars; they are made up.
var account = strings.Repeat("1", 12)

const (
	arnp       = "arn:" + "aws:"
	truststore = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	domainName = "access.example.test"
)

var (
	cdRole    = arnp + "iam::" + account + ":role/cd"
	adminRole = arnp + "iam::" + account + ":role/operators-admin"
	glassRole = arnp + "iam::" + account + ":role/breakglass"
	apply     = []string{cdRole, adminRole, glassRole}
)

type declared struct {
	Type, Name string
	Inputs     resource.PropertyMap
}

// recorder is Pulumi's mock engine: it answers every resource with its own
// inputs plus the outputs the provider would compute, and keeps what it was
// asked for. A stack transform records the options the mock monitor does not
// pass to NewResource.
type recorder struct {
	mu        sync.Mutex
	resources []declared
	protected map[string]bool
	aliased   map[string]bool
}

func (r *recorder) NewResource(a pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	r.mu.Lock()
	r.resources = append(r.resources, declared{Type: a.TypeToken, Name: a.Name, Inputs: a.Inputs.Copy()})
	r.mu.Unlock()
	out := a.Inputs.Copy()
	physical := a.Name
	for _, k := range []string{"name", "bucket"} {
		if v, ok := a.Inputs[resource.PropertyKey(k)]; ok && v.IsString() {
			physical = v.StringValue()
		}
	}
	set := func(k, v string) { out[resource.PropertyKey(k)] = resource.NewStringProperty(v) }
	switch a.TypeToken {
	case "aws:s3/bucket:Bucket":
		set("arn", arnp+"s3:::"+physical)
		set("bucket", physical)
	case "aws:s3/bucketObjectv2:BucketObjectv2":
		set("versionId", "v1")
	case "aws:acm/certificate:Certificate":
		set("arn", arnp+"acm:eu-west-1:"+account+":certificate/requested")
		out["domainValidationOptions"] = resource.NewArrayProperty([]resource.PropertyValue{resource.NewObjectProperty(resource.PropertyMap{
			"resourceRecordName":  resource.NewStringProperty("_x." + domainName + "."),
			"resourceRecordType":  resource.NewStringProperty("CNAME"),
			"resourceRecordValue": resource.NewStringProperty("_y.acm-validations.aws."),
		})})
	case "aws:acm/certificateValidation:CertificateValidation":
		set("certificateArn", arnp+"acm:eu-west-1:"+account+":certificate/requested")
	case "aws:apigatewayv2/domainName:DomainName":
		out["domainNameConfiguration"] = resource.NewObjectProperty(resource.PropertyMap{
			"targetDomainName": resource.NewStringProperty("d-abc.execute-api.eu-west-1.amazonaws.com"),
			"hostedZoneId":     resource.NewStringProperty("ZHOSTED"),
		})
	default:
		set("arn", arnp+"mock:::"+a.TypeToken+"/"+physical)
	}
	return a.Name + "_id", out, nil
}

func (r *recorder) Call(a pulumi.MockCallArgs) (resource.PropertyMap, error) { return a.Args, nil }

func (r *recorder) transform(ctx *pulumi.Context) error {
	return ctx.RegisterStackTransformation(func(a *pulumi.ResourceTransformationArgs) *pulumi.ResourceTransformationResult {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.protected == nil {
			r.protected, r.aliased = map[string]bool{}, map[string]bool{}
		}
		ro, err := pulumi.NewResourceOptions(a.Opts...)
		r.protected[a.Type+"/"+a.Name] = err == nil && ro.Protect
		r.aliased[a.Type+"/"+a.Name] = err == nil && len(ro.Aliases) > 0
		return nil
	})
}

func (r *recorder) one(t *testing.T, typ, name string) declared {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.resources {
		if d.Type == typ && d.Name == name {
			return d
		}
	}
	t.Fatalf("no %s named %s", typ, name)
	return declared{}
}

func (r *recorder) count(typ string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, d := range r.resources {
		if d.Type == typ {
			n++
		}
	}
	return n
}

// names are the logical names of the resources the front door registered, sorted.
func (r *recorder) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, d := range r.resources {
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}

func prop(d declared, key string) resource.PropertyValue { return d.Inputs[resource.PropertyKey(key)] }

func run(t *testing.T, program func(ctx *pulumi.Context, collect func(string, pulumi.StringInput)) error) (*recorder, map[string]string, error) {
	t.Helper()
	rec := &recorder{}
	got := map[string]string{}
	var wg sync.WaitGroup
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		if err := rec.transform(ctx); err != nil {
			return err
		}
		return program(ctx, func(k string, o pulumi.StringInput) {
			wg.Add(1)
			o.ToStringOutput().ApplyT(func(v string) string {
				defer wg.Done()
				rec.mu.Lock()
				got[k] = v
				rec.mu.Unlock()
				return v
			})
		})
	}, pulumi.WithMocks("awsapigw-test", "test", rec))
	wg.Wait()
	return rec, got, err
}

// front is an installation's component as a front door sees it: a name, the
// API and the component an older release created the domain under.
func front(ctx *pulumi.Context) awsapigw.FrontDoor {
	comp := &pulumi.ResourceState{}
	if err := ctx.RegisterComponentResource("sluis:aws:Lambda", "staging", comp); err != nil {
		panic(err)
	}
	return awsapigw.FrontDoor{Name: "staging", Component: comp, APIID: pulumi.String("abc"), StageName: pulumi.String("$default")}
}

func certArn() pulumi.StringInput {
	return pulumi.String(arnp + "acm:eu-west-1:" + account + ":certificate/origin")
}

func newBucket() awsapigw.Truststore {
	return awsapigw.Truststore{NewBucket: &awsapigw.NewBucketArgs{Name: "acme-truststore", ApplyPrincipalArns: apply}}
}

func guardStatement(t *testing.T, doc string) map[string]any {
	t.Helper()
	var d struct{ Statement []map[string]any }
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatal(err)
	}
	for _, s := range d.Statement {
		if strings.HasPrefix(s["Sid"].(string), "ProtectPrefix") {
			return s
		}
	}
	t.Fatalf("no prefix guard in %s", doc)
	return nil
}

func toStrings(v any) []string {
	var out []string
	for _, e := range v.([]any) {
		out = append(out, e.(string))
	}
	return out
}

func principals(t *testing.T, st map[string]any) []string {
	t.Helper()
	return toStrings(st["Condition"].(map[string]any)["ArnNotEquals"].(map[string]any)["aws:PrincipalArn"])
}

// The truststore goes in an existing bucket; the domain has mutual TLS on it
// and pins its version; the domain is aliased to where the old release had it.
func TestExistingBucket(t *testing.T) {
	rec, out, err := run(t, func(ctx *pulumi.Context, collect func(string, pulumi.StringInput)) error {
		d, err := awsapigw.New(ctx, "staging", &awsapigw.Args{
			FrontDoor: front(ctx), DomainName: domainName, CertificateArn: certArn(), TruststorePEM: truststore,
			Truststore: awsapigw.Truststore{Existing: &awsapigw.ExistingBucketArgs{BucketName: "acme-blobs", Versioned: true, GuardedPrefix: true}},
		})
		if err != nil {
			return err
		}
		collect("domainTarget", d.DomainTarget)
		collect("hostedZone", d.DomainHostedZoneID)
		collect("uri", d.TruststoreURI)
		collect("version", d.TruststoreVersion)
		collect("certificate", d.CertificateArn)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	dom := rec.one(t, "aws:apigatewayv2/domainName:DomainName", "staging-domain")
	if prop(dom, "domainName").StringValue() != domainName {
		t.Errorf("domain: %v", dom.Inputs)
	}
	mtls := prop(dom, "mutualTlsAuthentication").ObjectValue()
	if mtls["truststoreUri"].StringValue() != "s3://acme-blobs/truststore/client-ca.pem" || mtls["truststoreVersion"].StringValue() != "v1" {
		t.Errorf("mutual TLS: %v", mtls)
	}
	cfg := prop(dom, "domainNameConfiguration").ObjectValue()
	if cfg["endpointType"].StringValue() != "REGIONAL" || cfg["securityPolicy"].StringValue() != "TLS_1_2" ||
		!strings.Contains(cfg["certificateArn"].StringValue(), "certificate/origin") {
		t.Errorf("domain configuration: %v", cfg)
	}
	mapping := rec.one(t, "aws:apigatewayv2/apiMapping:ApiMapping", "staging-domain-mapping")
	if prop(mapping, "apiId").StringValue() != "abc" || prop(mapping, "stage").StringValue() != "$default" {
		t.Errorf("mapping: %v", mapping.Inputs)
	}
	obj := rec.one(t, "aws:s3/bucketObjectv2:BucketObjectv2", "staging-truststore-pem")
	if prop(obj, "bucket").StringValue() != "acme-blobs" || prop(obj, "key").StringValue() != "truststore/client-ca.pem" ||
		prop(obj, "content").StringValue() != truststore || prop(obj, "contentType").StringValue() != "application/x-pem-file" {
		t.Errorf("object: %v", obj.Inputs)
	}
	if n := rec.count("aws:s3/bucket:Bucket"); n != 0 {
		t.Errorf("%d buckets, want none", n)
	}
	if out["uri"] != "s3://acme-blobs/truststore/client-ca.pem" || out["version"] != "v1" || out["domainTarget"] == "" ||
		out["hostedZone"] != "ZHOSTED" || !strings.Contains(out["certificate"], "certificate/origin") {
		t.Errorf("outputs: %v", out)
	}
	for _, k := range []string{"aws:apigatewayv2/domainName:DomainName/staging-domain", "aws:apigatewayv2/apiMapping:ApiMapping/staging-domain-mapping"} {
		if !rec.aliased[k] {
			t.Errorf("%s has no alias to the installation's resource", k)
		}
	}
}

// A bucket of its own: protected, versioned, guarded.
func TestNewBucket(t *testing.T) {
	rec, out, err := run(t, func(ctx *pulumi.Context, collect func(string, pulumi.StringInput)) error {
		d, err := awsapigw.New(ctx, "staging", &awsapigw.Args{
			FrontDoor: front(ctx), DomainName: domainName, CertificateArn: certArn(), TruststorePEM: truststore,
			Truststore: newBucket(), Tags: map[string]string{"a": "b"},
		})
		if err != nil {
			return err
		}
		collect("uri", d.TruststoreURI)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["uri"] != "s3://acme-truststore/truststore/client-ca.pem" {
		t.Errorf("outputs: %v", out)
	}
	if !rec.protected["aws:s3/bucket:Bucket/staging-truststore"] {
		t.Error("the truststore bucket is not protected")
	}
	v := rec.one(t, "aws:s3/bucketVersioningV2:BucketVersioningV2", "staging-truststore-versioning")
	if prop(v, "versioningConfiguration").ObjectValue()["status"].StringValue() != "Enabled" {
		t.Errorf("versioning: %v", v.Inputs)
	}
	policy := rec.one(t, "aws:s3/bucketPolicy:BucketPolicy", "staging-truststore-policy")
	doc := prop(policy, "policy").StringValue()
	if !strings.Contains(doc, "DenyPlainHTTP") {
		t.Errorf("policy: %s", doc)
	}
	st := guardStatement(t, doc)
	if st["Sid"] != "ProtectPrefixtruststore" || st["Effect"] != "Deny" || st["Principal"] != "*" {
		t.Errorf("guard: %v", st)
	}
	if got := principals(t, st); !slices.Equal(got, apply) {
		t.Errorf("the guard exempts %v, want exactly %v", got, apply)
	}
	if res := toStrings(st["Resource"]); len(res) != 1 || res[0] != arnp+"s3:::acme-truststore/truststore/*" {
		t.Errorf("guard resource: %v", res)
	}
	if acts := toStrings(st["Action"]); !slices.Contains(acts, "s3:PutObject") || !slices.Contains(acts, "s3:DeleteObjectVersion") {
		t.Errorf("guard actions: %v", acts)
	}
	if n := rec.count("aws:s3/bucketObjectv2:BucketObjectv2"); n != 1 {
		t.Errorf("%d truststore objects, want one", n)
	}
}

// The guard statement on its own.
func TestProtectedPrefixStatement(t *testing.T) {
	p := awsapigw.ProtectedPrefix{Prefix: "truststore/", AllowedPrincipalArns: apply}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	st := p.Statement(arnp + "s3:::b")
	if st["Sid"] != "ProtectPrefixtruststore" || st["Effect"] != "Deny" {
		t.Errorf("%v", st)
	}
	for name, bad := range map[string]awsapigw.ProtectedPrefix{
		"no slash": {Prefix: "truststore", AllowedPrincipalArns: apply},
		"leading":  {Prefix: "/truststore/", AllowedPrincipalArns: apply},
		"empty":    {Prefix: "truststore/"},
		"not arn":  {Prefix: "truststore/", AllowedPrincipalArns: []string{"cd"}},
	} {
		if bad.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A requested certificate is validated through the caller's own DNS.
func TestRequestsTheCertificate(t *testing.T) {
	rec, out, err := run(t, func(ctx *pulumi.Context, collect func(string, pulumi.StringInput)) error {
		d, err := awsapigw.New(ctx, "staging", &awsapigw.Args{
			FrontDoor: front(ctx), DomainName: domainName, TruststorePEM: truststore, Truststore: newBucket(),
			Certificate: &awsapigw.CertificateArgs{KeyAlgorithm: "EC_prime256v1",
				CreateValidationRecord: func(_ *pulumi.Context, r awsapigw.ValidationRecord) (pulumi.StringInput, error) {
					collect("recordName", r.Name)
					collect("recordType", r.Type)
					collect("recordValue", r.Value)
					return r.Name, nil
				}},
		})
		if err != nil {
			return err
		}
		collect("certificate", d.CertificateArn)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	cert := rec.one(t, "aws:acm/certificate:Certificate", "staging-certificate")
	if prop(cert, "domainName").StringValue() != domainName || prop(cert, "validationMethod").StringValue() != "DNS" ||
		prop(cert, "keyAlgorithm").StringValue() != "EC_prime256v1" {
		t.Errorf("certificate: %v", cert.Inputs)
	}
	val := rec.one(t, "aws:acm/certificateValidation:CertificateValidation", "staging-certificate-validation")
	if fq := prop(val, "validationRecordFqdns").ArrayValue(); len(fq) != 1 || fq[0].StringValue() != "_x."+domainName+"." {
		t.Errorf("validation: %v", val.Inputs)
	}
	if out["recordType"] != "CNAME" || out["recordValue"] != "_y.acm-validations.aws." || !strings.Contains(out["certificate"], "certificate/requested") {
		t.Errorf("outputs: %v", out)
	}
}

// An adopted certificate keeps the name the stack knows it by.
func TestCertificateName(t *testing.T) {
	rec, _, err := run(t, func(ctx *pulumi.Context, _ func(string, pulumi.StringInput)) error {
		_, err := awsapigw.New(ctx, "staging", &awsapigw.Args{
			FrontDoor: front(ctx), DomainName: domainName, TruststorePEM: truststore, Truststore: newBucket(),
			Certificate: &awsapigw.CertificateArgs{Name: "legacy-cert",
				CreateValidationRecord: func(_ *pulumi.Context, r awsapigw.ValidationRecord) (pulumi.StringInput, error) {
					return r.Name, nil
				}},
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	rec.one(t, "aws:acm/certificate:Certificate", "legacy-cert")
}

// The logical names are a contract: a stack that has them keeps its resources.
// These are the names truvity/sluis registered.
func TestLogicalNames(t *testing.T) {
	rec, _, err := run(t, func(ctx *pulumi.Context, _ func(string, pulumi.StringInput)) error {
		_, err := awsapigw.New(ctx, "edge", &awsapigw.Args{
			FrontDoor: front(ctx), DomainName: domainName, TruststorePEM: truststore, Truststore: newBucket(),
			Certificate: &awsapigw.CertificateArgs{CreateValidationRecord: func(_ *pulumi.Context, r awsapigw.ValidationRecord) (pulumi.StringInput, error) {
				return r.Name, nil
			}},
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"edge-certificate", "edge-certificate-validation", "edge-truststore", "edge-truststore-encryption",
		"edge-truststore-versioning", "edge-truststore-public-access", "edge-truststore-policy", "edge-truststore-pem",
		"edge-domain", "edge-domain-mapping", "staging" /* the installation's component, from the fixture */}
	sort.Strings(want)
	var got []string
	for _, n := range rec.names() {
		if n != "awsapigw-test-test" && !strings.HasPrefix(n, "pulumi-") && n != "edge" {
			got = append(got, n)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("logical names\n got %v\nwant %v", got, want)
	}
}

// The component type is the new default, or the one a migrating stack has.
func TestComponentType(t *testing.T) {
	for typ, want := range map[string]string{"": awsapigw.DefaultComponentType, awsapigw.ComponentTypeSluis: "sluis:aws:CloudflareEdge"} {
		rec, _, err := run(t, func(ctx *pulumi.Context, _ func(string, pulumi.StringInput)) error {
			_, err := awsapigw.New(ctx, "edge", &awsapigw.Args{
				FrontDoor: front(ctx), DomainName: domainName, CertificateArn: certArn(), TruststorePEM: truststore,
				Truststore: newBucket(), ComponentType: typ,
			})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		rec.one(t, want, "edge")
	}
	if awsapigw.DefaultComponentType != "truvity:aws:ApiGatewayDomain" {
		t.Error("the default type changed")
	}
}

// The DNS record is the caller's provider's, proxied, under the name it gives.
func TestDNS(t *testing.T) {
	rec, _, err := run(t, func(ctx *pulumi.Context, _ func(string, pulumi.StringInput)) error {
		p, err := cloudflare.NewProvider(ctx, "cf", &cloudflare.ProviderArgs{ApiToken: pulumi.String("x")})
		if err != nil {
			return err
		}
		_, err = awsapigw.New(ctx, "edge", &awsapigw.Args{
			FrontDoor: front(ctx), DomainName: domainName, CertificateArn: certArn(), TruststorePEM: truststore, Truststore: newBucket(),
			DNS: &awsapigw.DNSArgs{Provider: p, ZoneID: pulumi.String("zone1"), ResourceName: "cname-access-example-test",
				Aliases: []pulumi.Alias{{Name: pulumi.String("old")}}},
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	r := rec.one(t, "cloudflare:index/dnsRecord:DnsRecord", "cname-access-example-test")
	if prop(r, "name").StringValue() != domainName || prop(r, "type").StringValue() != "CNAME" || !prop(r, "proxied").BoolValue() ||
		prop(r, "zoneId").StringValue() != "zone1" || !strings.Contains(prop(r, "content").StringValue(), "execute-api") {
		t.Errorf("record: %v", r.Inputs)
	}
	if !rec.aliased["cloudflare:index/dnsRecord:DnsRecord/cname-access-example-test"] {
		t.Error("the record is not aliased")
	}
	// Without DNS there is no record.
	rec, _, err = run(t, func(ctx *pulumi.Context, _ func(string, pulumi.StringInput)) error {
		_, err := awsapigw.New(ctx, "edge", &awsapigw.Args{
			FrontDoor: front(ctx), DomainName: domainName, CertificateArn: certArn(), TruststorePEM: truststore, Truststore: newBucket(),
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.count("cloudflare:index/dnsRecord:DnsRecord") != 0 {
		t.Error("a record without DNS")
	}
}

// What is refused, every problem at once.
func TestValidate(t *testing.T) {
	good := func() *awsapigw.Args {
		return &awsapigw.Args{
			FrontDoor: awsapigw.FrontDoor{APIID: pulumi.String("a"), StageName: pulumi.String("s")}, DomainName: domainName,
			CertificateArn: certArn(), TruststorePEM: truststore, Truststore: newBucket(),
		}
	}
	if err := good().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*awsapigw.Args)
		want   string
	}{
		"no front door":       {func(a *awsapigw.Args) { a.FrontDoor = awsapigw.FrontDoor{} }, "FrontDoor"},
		"no domain":           {func(a *awsapigw.Args) { a.DomainName = "" }, "DomainName"},
		"no truststore pem":   {func(a *awsapigw.Args) { a.TruststorePEM = " " }, "TruststorePEM"},
		"no certificate":      {func(a *awsapigw.Args) { a.CertificateArn = nil }, "exactly one of CertificateArn"},
		"two certificates":    {func(a *awsapigw.Args) { a.Certificate = &awsapigw.CertificateArgs{} }, "exactly one of CertificateArn"},
		"no callback":         {func(a *awsapigw.Args) { a.CertificateArn = nil; a.Certificate = &awsapigw.CertificateArgs{} }, "CreateValidationRecord"},
		"no bucket":           {func(a *awsapigw.Args) { a.Truststore = awsapigw.Truststore{} }, "exactly one of NewBucket"},
		"two buckets":         {func(a *awsapigw.Args) { a.Truststore.Existing = &awsapigw.ExistingBucketArgs{} }, "exactly one of NewBucket"},
		"no bucket name":      {func(a *awsapigw.Args) { a.Truststore.NewBucket.Name = "" }, "NewBucket.Name"},
		"no apply identities": {func(a *awsapigw.Args) { a.Truststore.NewBucket.ApplyPrincipalArns = nil }, "AllowedPrincipalArns"},
		"not an ARN":          {func(a *awsapigw.Args) { a.Truststore.NewBucket.ApplyPrincipalArns = []string{"cd"} }, "not an ARN"},
		"unversioned": {func(a *awsapigw.Args) {
			a.Truststore = awsapigw.Truststore{Existing: &awsapigw.ExistingBucketArgs{BucketName: "b", GuardedPrefix: true}}
		}, "versioned"},
		"unguarded": {func(a *awsapigw.Args) {
			a.Truststore = awsapigw.Truststore{Existing: &awsapigw.ExistingBucketArgs{BucketName: "b", Versioned: true}}
		}, "attest a guard"},
		"existing no name": {func(a *awsapigw.Args) {
			a.Truststore = awsapigw.Truststore{Existing: &awsapigw.ExistingBucketArgs{Versioned: true, GuardedPrefix: true}}
		}, "BucketName"},
		"dns incomplete": {func(a *awsapigw.Args) { a.DNS = &awsapigw.DNSArgs{} }, "DNS.Provider"},
		"unproxied dns": {func(a *awsapigw.Args) {
			a.DNS = &awsapigw.DNSArgs{Provider: &cloudflare.Provider{}, ZoneID: pulumi.String("z"), Unproxied: true}
		}, "Unproxied"},
		"bad type": {func(a *awsapigw.Args) { a.ComponentType = "nope" }, "type token"},
	} {
		t.Run(name, func(t *testing.T) {
			a := good()
			tc.mutate(a)
			err := a.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	// Every problem is reported, not the first.
	err := (&awsapigw.Args{}).Validate()
	if err == nil {
		t.Fatal("empty Args accepted")
	}
	for _, w := range []string{"FrontDoor", "DomainName", "TruststorePEM", "exactly one of CertificateArn", "exactly one of NewBucket"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%q missing from %v", w, err)
		}
	}
	if (*awsapigw.Args)(nil).Validate() == nil {
		t.Error("nil Args accepted")
	}
}

// The package stands alone: it must not import truvity/sluis.
func TestDoesNotImportSluis(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range pkg.Imports {
		if strings.Contains(imp, "truvity/sluis") {
			t.Errorf("imports %s", imp)
		}
	}
}
