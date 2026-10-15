// Package awsapigw is the AWS API Gateway "front door" pattern: an API Gateway
// HTTP API behind a regional custom domain with mutual TLS that accepts only
// Cloudflare's client certificate (Authenticated Origin Pulls), the truststore
// that says so, the ACM certificate for the domain and, optionally, the
// proxied Cloudflare CNAME that points the name at it.
//
// It takes the API as a FrontDoor (the API id and stage, plus, for a stack
// that created the domain elsewhere first, the component whose children the
// domain is aliased from) and imports no sluis package. It was moved here
// from truvity/sluis deploy/pulumi/edge/cloudflare; docs/cloudflare/awsapigw.md
// has the migration with the exact names.
package awsapigw

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/acm"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/apigatewayv2"
	"github.com/pulumi/pulumi-aws/sdk/v7/go/aws/s3"
	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// DefaultComponentType is the Pulumi type token of the component by default.
// A stack that already has the component registered under another type (the
// sluis one is ComponentTypeSluis) passes that in Args.ComponentType.
const DefaultComponentType = "truvity:aws:ApiGatewayDomain"

// ComponentTypeSluis is the type token truvity/sluis registered the same
// component under; pass it as Args.ComponentType to move without a replace.
const ComponentTypeSluis = "sluis:aws:CloudflareEdge"

// TruststorePrefix is where the truststore lives in its bucket, and
// TruststoreKey the object: ONE object, versioned, whose version the domain
// pins.
const (
	TruststorePrefix = "truststore/"
	TruststoreKey    = TruststorePrefix + "client-ca.pem"
)

// FrontDoor is what the pattern needs of the installation: the HTTP API to put
// a domain in front of. Its fields are those of sluis's Lambda.FrontDoor().
type FrontDoor struct {
	// Name is the component's name. The domain and its mapping are aliased to
	// Name+"-domain" and Name+"-domain-mapping" under Component, so that a stack
	// that created them there moves without replacing them. Empty: no alias.
	Name string
	// Component is the parent of those aliases. Nil: no alias.
	Component pulumi.Resource
	// APIID and StageName are the HTTP API and its stage. Required.
	APIID, StageName pulumi.StringInput
}

// ValidationRecord is the DNS record ACM asks for to prove the domain.
type ValidationRecord struct {
	Name, Type, Value pulumi.StringOutput
}

// CertificateArgs asks for the ACM certificate to be requested, with DNS
// validation.
type CertificateArgs struct {
	// KeyAlgorithm is the certificate's key algorithm ("EC_prime256v1",
	// "RSA_2048", ...). Default: the provider's.
	KeyAlgorithm string
	// Name is the certificate's logical resource name, for adopting a
	// certificate the stack already has under another name. Default
	// "<name>-certificate". The validation keeps "<name>-certificate-validation".
	Name string
	// ValidationName is the logical name of the acm.CertificateValidation.
	// Default "<name>-certificate-validation". Set it, with Aliases, to adopt a
	// validation the stack already has under another name.
	ValidationName string
	// Aliases are the certificate's old identities, to move an existing
	// certificate here without replacing it. For one that sat at the top of
	// another stack, NoParentAliases(oldName). Default none.
	Aliases []pulumi.Alias
	// ValidationAliases are the same for the acm.CertificateValidation.
	ValidationAliases []pulumi.Alias
	// CreateValidationRecord creates the record in the estate's DNS and returns
	// its fully qualified name, which ACM is waited on to see. Exactly one of
	// CreateValidationRecord and ValidationRecord.
	CreateValidationRecord func(ctx *pulumi.Context, record ValidationRecord) (pulumi.StringInput, error)
	// ValidationRecord has the package make the Cloudflare record itself, so
	// that its logical name and aliases can be set to adopt an existing one.
	ValidationRecord *ValidationRecordArgs
}

// ValidationRecordArgs is the Cloudflare record ACM validates the domain by:
// DNS-only (a proxied record would answer ACM with Cloudflare's addresses),
// automatic TTL, with the name, type and value ACM asks for (trailing dots
// removed).
type ValidationRecordArgs struct {
	// Provider is the Cloudflare provider the record is made with. Required.
	Provider pulumi.ProviderResource
	// ZoneID is the zone of the domain. Required.
	ZoneID pulumi.StringInput
	// ResourceName is the record's logical name. Default
	// "<name>-certificate-validation-record".
	ResourceName string
	// Aliases move an existing record here without replacing it.
	Aliases []pulumi.Alias
	// Comment is the record's comment. Default none.
	Comment string
}

// NoParentAliases are aliases, one per old name, for a resource that was at the
// top of another stack (it had no parent) and was moved here with `pulumi
// state move`, where it is a child of the component. The old URN has the
// resource's own type, so only the name is given.
func NoParentAliases(oldNames ...string) []pulumi.Alias {
	out := make([]pulumi.Alias, 0, len(oldNames))
	for _, n := range oldNames {
		out = append(out, pulumi.Alias{Name: pulumi.String(n), NoParent: pulumi.Bool(true)})
	}
	return out
}

// NewBucketArgs is a small S3 bucket of the pattern's own for the truststore.
type NewBucketArgs struct {
	// Name is the bucket's name. Global. Required.
	Name string
	// ApplyPrincipalArns are the identities that may write the truststore: the
	// role the stack is applied with, the operators' admin role, a break-glass
	// role. Every other principal is denied writes under TruststorePrefix by
	// the bucket policy. Required.
	ApplyPrincipalArns []string
	// Tags are put on the bucket, over Args.Tags.
	Tags map[string]string
}

// ExistingBucketArgs puts the truststore in a bucket that is not the pattern's.
// The pattern cannot see the bucket's configuration, so the caller attests to
// it, and the pattern refuses an attestation that is not given.
type ExistingBucketArgs struct {
	// BucketName is the bucket, in the domain's region. Required.
	BucketName string
	// Versioned attests that the bucket is versioned: the domain pins the
	// truststore's version. Must be true.
	Versioned bool
	// GuardedPrefix attests that the bucket denies writes under TruststorePrefix
	// to every identity but the apply identities (ProtectedPrefix.Statement):
	// otherwise whatever writes the bucket could replace the truststore. Must
	// be true.
	GuardedPrefix bool
}

// Truststore is where the truststore object goes: exactly one field.
type Truststore struct {
	NewBucket *NewBucketArgs
	Existing  *ExistingBucketArgs
}

// DNSArgs asks for the proxied CNAME of DomainName to the domain's target, made
// with the caller's Cloudflare provider.
type DNSArgs struct {
	// Provider is the Cloudflare provider (a *cloudflare.Provider) the record
	// is created with. Required.
	Provider pulumi.ProviderResource
	// ZoneID is the zone of DomainName. Required.
	ZoneID pulumi.StringInput
	// Name is the record's name. Default DomainName.
	Name string
	// Unproxied would make the record DNS-only. The zero value is proxied,
	// because Authenticated Origin Pulls works only through Cloudflare's proxy
	// and the domain always demands a client certificate: Validate refuses
	// Unproxied, there being no configuration in which it works.
	Unproxied bool
	// ResourceName is the record's logical name. Default "<name>-dns". Set it
	// to the name the stack already uses to adopt an existing record.
	ResourceName string
	// Aliases move an existing record here without replacing it: NoParentAliases
	// for one that was at the top of another stack, or an Alias with ParentURN
	// (the old parent's URN, which need not exist in this stack) for one that
	// was under a component there.
	Aliases []pulumi.Alias
	// Comment is the record's comment. Default none.
	Comment string
}

// Args is the front door.
type Args struct {
	// FrontDoor is the installation's HTTP API. Required.
	FrontDoor FrontDoor
	// DomainName is the custom domain. Required.
	DomainName string
	// CertificateArn is an ACM certificate for DomainName in the API's region,
	// which the caller supplies. Exactly one of CertificateArn and Certificate.
	CertificateArn pulumi.StringInput
	// Certificate requests the certificate here instead, with DNS validation.
	Certificate *CertificateArgs
	// TruststorePEM is the PEM bundle of the CAs a client certificate must chain
	// to: for Authenticated Origin Pulls, Cloudflare's origin-pull CA. Required.
	TruststorePEM string
	// Truststore is where it goes. Exactly one field.
	Truststore Truststore
	// DNS, when set, creates the proxied CNAME. Default none: DNS is the
	// caller's.
	DNS *DNSArgs
	// ComponentType is the component's Pulumi type token. Default
	// DefaultComponentType.
	ComponentType string
	// Tags are put on what the pattern creates. Default none.
	Tags map[string]string
}

// Validate reports every problem in the arguments at once.
func (a *Args) Validate() error {
	if a == nil {
		return errors.New("awsapigw: Args is nil")
	}
	var errs []error
	add := func(format string, v ...any) { errs = append(errs, fmt.Errorf("awsapigw: "+format, v...)) }
	if a.FrontDoor.APIID == nil || a.FrontDoor.StageName == nil {
		add("Args.FrontDoor.APIID and StageName are required")
	}
	if a.DomainName == "" {
		add("Args.DomainName is required")
	}
	if strings.TrimSpace(a.TruststorePEM) == "" {
		add("Args.TruststorePEM is required")
	}
	if (a.CertificateArn == nil) == (a.Certificate == nil) {
		add("Args: set exactly one of CertificateArn and Certificate")
	}
	if c := a.Certificate; c != nil {
		switch {
		case (c.CreateValidationRecord == nil) == (c.ValidationRecord == nil):
			add("Args.Certificate: set exactly one of CreateValidationRecord and ValidationRecord")
		case c.ValidationRecord != nil:
			if c.ValidationRecord.Provider == nil {
				add("Args.Certificate.ValidationRecord.Provider is required")
			}
			if c.ValidationRecord.ZoneID == nil {
				add("Args.Certificate.ValidationRecord.ZoneID is required")
			}
		}
	}
	ts := a.Truststore
	switch {
	case (ts.NewBucket == nil) == (ts.Existing == nil):
		add("Args.Truststore: set exactly one of NewBucket and Existing")
	case ts.NewBucket != nil:
		if ts.NewBucket.Name == "" {
			add("Args.Truststore.NewBucket.Name is required")
		}
		if err := a.guard(ts.NewBucket.ApplyPrincipalArns).Validate(); err != nil {
			errs = append(errs, err)
		}
	default:
		e := ts.Existing
		if e.BucketName == "" {
			add("Args.Truststore.Existing.BucketName is required")
		}
		if !e.Versioned {
			add("Args.Truststore.Existing is not attested versioned: the domain pins the truststore's version")
		}
		if !e.GuardedPrefix {
			add("Args.Truststore.Existing does not attest a guard on %q: whatever writes the bucket could replace the truststore", TruststorePrefix)
		}
	}
	if d := a.DNS; d != nil {
		if d.Provider == nil {
			add("Args.DNS.Provider is required")
		}
		if d.ZoneID == nil {
			add("Args.DNS.ZoneID is required")
		}
		if d.Unproxied {
			add("Args.DNS.Unproxied is refused: the domain demands a client certificate only Cloudflare's proxy presents, " +
				"so a DNS-only record would be rejected by every client")
		}
	}
	if t := a.ComponentType; t != "" && strings.Count(t, ":") != 2 {
		add("Args.ComponentType %q is not a type token (package:module:Type)", t)
	}
	return errors.Join(errs...)
}

func (a *Args) guard(principals []string) ProtectedPrefix {
	return ProtectedPrefix{Prefix: TruststorePrefix, AllowedPrincipalArns: principals}
}

// Domain is the component. Its fields are the outputs.
type Domain struct {
	pulumi.ResourceState

	// DomainTarget and DomainHostedZoneID are what DNS for the custom domain
	// points at (a CNAME, or an alias record).
	DomainTarget       pulumi.StringOutput
	DomainHostedZoneID pulumi.StringOutput
	// CertificateArn is the certificate the domain uses.
	CertificateArn pulumi.StringOutput
	// TruststoreURI and TruststoreVersion are where the client-CA bundle is,
	// and the version the domain pins.
	TruststoreURI     pulumi.StringOutput
	TruststoreVersion pulumi.StringOutput
}

// New creates the custom domain with mutual TLS, its mapping to the API, the
// truststore object and, as asked, the certificate, the truststore bucket and
// the DNS record.
//
// The domain is regional, TLS 1.2, and demands a client certificate that chains
// to the truststore. Keeping the default execute-api endpoint off (it is a way
// round the client certificate) is the API's, not this.
//
// Authenticated Origin Pulls is the zone's setting (tls_client_auth, which
// cloudflare/zone sets with AuthenticatedOriginPulls): without it Cloudflare
// presents no client certificate and the domain refuses every request.
//
// The AWS provider is the caller's to choose, through opts.
func New(ctx *pulumi.Context, name string, args *Args, opts ...pulumi.ResourceOption) (*Domain, error) {
	if err := args.Validate(); err != nil {
		return nil, err
	}
	a := *args
	typ := a.ComponentType
	if typ == "" {
		typ = DefaultComponentType
	}
	out := &Domain{}
	if err := ctx.RegisterComponentResource(typ, name, out, opts...); err != nil {
		return nil, err
	}
	child := pulumi.Parent(out)
	var tags pulumi.StringMapInput
	if len(a.Tags) > 0 {
		tags = pulumi.ToStringMap(a.Tags)
	}

	// ---- the certificate
	certArn := a.CertificateArn
	if c := a.Certificate; c != nil {
		certName := name + "-certificate"
		if c.Name != "" {
			certName = c.Name
		}
		cargs := &acm.CertificateArgs{DomainName: pulumi.String(a.DomainName), ValidationMethod: pulumi.String("DNS"), Tags: tags}
		if c.KeyAlgorithm != "" {
			cargs.KeyAlgorithm = pulumi.String(c.KeyAlgorithm)
		}
		copts := []pulumi.ResourceOption{child}
		if len(c.Aliases) > 0 {
			copts = append(copts, pulumi.Aliases(c.Aliases))
		}
		cert, err := acm.NewCertificate(ctx, certName, cargs, copts...)
		if err != nil {
			return nil, fmt.Errorf("awsapigw certificate: %w", err)
		}
		rec := ValidationRecord{
			Name: validationField(cert, func(o acm.CertificateDomainValidationOption) *string { return o.ResourceRecordName }),
			Type: validationField(cert, func(o acm.CertificateDomainValidationOption) *string { return o.ResourceRecordType }),
			Value: validationField(cert, func(o acm.CertificateDomainValidationOption) *string {
				return o.ResourceRecordValue
			}),
		}
		var fqdn pulumi.StringInput
		if v := c.ValidationRecord; v != nil {
			fqdn, err = newValidationRecord(ctx, name, v, rec, child)
		} else {
			fqdn, err = c.CreateValidationRecord(ctx, rec)
		}
		if err != nil {
			return nil, fmt.Errorf("awsapigw certificate validation record: %w", err)
		}
		validationName := name + "-certificate-validation"
		if c.ValidationName != "" {
			validationName = c.ValidationName
		}
		vopts := []pulumi.ResourceOption{child}
		if len(c.ValidationAliases) > 0 {
			vopts = append(vopts, pulumi.Aliases(c.ValidationAliases))
		}
		valid, err := acm.NewCertificateValidation(ctx, validationName, &acm.CertificateValidationArgs{
			CertificateArn:        cert.Arn,
			ValidationRecordFqdns: pulumi.StringArray{fqdn},
		}, vopts...)
		if err != nil {
			return nil, fmt.Errorf("awsapigw certificate validation: %w", err)
		}
		certArn = valid.CertificateArn
	}

	// ---- the truststore: one object, in a bucket of its own or an existing one
	var bucketID, bucketName pulumi.StringInput
	var after []pulumi.Resource
	if e := a.Truststore.Existing; e != nil {
		bucketID, bucketName = pulumi.String(e.BucketName), pulumi.String(e.BucketName)
	} else {
		b, err := newTruststoreBucket(ctx, name, &a, child)
		if err != nil {
			return nil, err
		}
		bucketID, bucketName, after = b.bucket.ID(), b.bucket.Bucket, b.ready
	}
	obj, err := s3.NewBucketObjectv2(ctx, name+"-truststore-pem", &s3.BucketObjectv2Args{
		Bucket:      bucketID,
		Key:         pulumi.String(TruststoreKey),
		Content:     pulumi.String(a.TruststorePEM),
		ContentType: pulumi.String("application/x-pem-file"),
	}, child, pulumi.DependsOn(after))
	if err != nil {
		return nil, fmt.Errorf("awsapigw truststore object: %w", err)
	}

	// ---- the domain, which pins the version of the object it was given
	fd := a.FrontDoor
	aliases := func(suffix string) pulumi.ResourceOption {
		if fd.Name == "" || fd.Component == nil {
			return pulumi.Aliases(nil)
		}
		return pulumi.Aliases([]pulumi.Alias{{Name: pulumi.String(fd.Name + suffix), Parent: fd.Component}})
	}
	uri := pulumi.Sprintf("s3://%s/%s", bucketName, obj.Key)
	domain, err := apigatewayv2.NewDomainName(ctx, name+"-domain", &apigatewayv2.DomainNameArgs{
		DomainName: pulumi.String(a.DomainName),
		DomainNameConfiguration: &apigatewayv2.DomainNameDomainNameConfigurationArgs{
			CertificateArn: certArn,
			EndpointType:   pulumi.String("REGIONAL"),
			SecurityPolicy: pulumi.String("TLS_1_2"),
		},
		MutualTlsAuthentication: &apigatewayv2.DomainNameMutualTlsAuthenticationArgs{
			TruststoreUri:     uri,
			TruststoreVersion: obj.VersionId,
		},
		Tags: tags,
	}, child, aliases("-domain"))
	if err != nil {
		return nil, fmt.Errorf("awsapigw custom domain: %w", err)
	}
	if _, err := apigatewayv2.NewApiMapping(ctx, name+"-domain-mapping", &apigatewayv2.ApiMappingArgs{
		ApiId: fd.APIID, DomainName: domain.DomainName, Stage: fd.StageName,
	}, child, aliases("-domain-mapping")); err != nil {
		return nil, fmt.Errorf("awsapigw api mapping: %w", err)
	}

	out.DomainTarget = domain.DomainNameConfiguration.ApplyT(func(c apigatewayv2.DomainNameDomainNameConfiguration) string {
		if c.TargetDomainName == nil {
			return ""
		}
		return *c.TargetDomainName
	}).(pulumi.StringOutput)
	out.DomainHostedZoneID = domain.DomainNameConfiguration.ApplyT(func(c apigatewayv2.DomainNameDomainNameConfiguration) string {
		if c.HostedZoneId == nil {
			return ""
		}
		return *c.HostedZoneId
	}).(pulumi.StringOutput)

	// ---- the proxied CNAME, in the caller's zone
	if d := a.DNS; d != nil {
		rname := d.ResourceName
		if rname == "" {
			rname = name + "-dns"
		}
		host := d.Name
		if host == "" {
			host = a.DomainName
		}
		ropts := []pulumi.ResourceOption{child, pulumi.Provider(d.Provider)}
		if len(d.Aliases) > 0 {
			ropts = append(ropts, pulumi.Aliases(d.Aliases))
		}
		rargs := &cloudflare.DnsRecordArgs{
			ZoneId:  d.ZoneID,
			Name:    pulumi.String(host),
			Type:    pulumi.String("CNAME"),
			Content: out.DomainTarget,
			Proxied: pulumi.Bool(true),
			// 1 = automatic, required for a proxied record.
			Ttl: pulumi.Float64(1),
		}
		if d.Comment != "" {
			rargs.Comment = pulumi.String(d.Comment)
		}
		if _, err := cloudflare.NewDnsRecord(ctx, rname, rargs, ropts...); err != nil {
			return nil, fmt.Errorf("awsapigw dns record: %w", err)
		}
	}

	out.CertificateArn = certArn.ToStringOutput()
	out.TruststoreURI = uri
	out.TruststoreVersion = obj.VersionId
	if err := ctx.RegisterResourceOutputs(out, pulumi.Map{
		"domainTarget": out.DomainTarget, "domainHostedZoneId": out.DomainHostedZoneID, "certificateArn": out.CertificateArn,
		"truststoreUri": out.TruststoreURI, "truststoreVersion": out.TruststoreVersion,
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// newValidationRecord makes the DNS-only record ACM validates by and returns
// its name, which the validation waits on.
func newValidationRecord(
	ctx *pulumi.Context, name string, v *ValidationRecordArgs, rec ValidationRecord, child pulumi.ResourceOption,
) (pulumi.StringInput, error) {
	rname := v.ResourceName
	if rname == "" {
		rname = name + "-certificate-validation-record"
	}
	trim := func(o pulumi.StringOutput) pulumi.StringOutput {
		return o.ApplyT(func(s string) string { return strings.TrimSuffix(s, ".") }).(pulumi.StringOutput)
	}
	opts := []pulumi.ResourceOption{child, pulumi.Provider(v.Provider)}
	if len(v.Aliases) > 0 {
		opts = append(opts, pulumi.Aliases(v.Aliases))
	}
	args := &cloudflare.DnsRecordArgs{
		ZoneId:  v.ZoneID,
		Name:    trim(rec.Name),
		Type:    rec.Type,
		Content: trim(rec.Value),
		Ttl:     pulumi.Float64(1),
		// GREY: a proxied record answers ACM with Cloudflare's addresses.
		Proxied: pulumi.Bool(false),
	}
	if v.Comment != "" {
		args.Comment = pulumi.String(v.Comment)
	}
	r, err := cloudflare.NewDnsRecord(ctx, rname, args, opts...)
	if err != nil {
		return nil, err
	}
	return r.Name, nil
}

// validationField is one field of the certificate's (single) DNS validation record.
func validationField(c *acm.Certificate, f func(acm.CertificateDomainValidationOption) *string) pulumi.StringOutput {
	return c.DomainValidationOptions.ApplyT(func(o []acm.CertificateDomainValidationOption) string {
		if len(o) == 0 || f(o[0]) == nil {
			return ""
		}
		return *f(o[0])
	}).(pulumi.StringOutput)
}

type truststoreBucket struct {
	bucket *s3.Bucket
	// ready is what the object waits for: versioning on and the policy in place.
	ready []pulumi.Resource
}

// newTruststoreBucket is the pattern's own small bucket: encrypted, versioned,
// closed to the public and to plain HTTP, protected, with writes under the
// truststore prefix denied to every principal but the apply identities.
func newTruststoreBucket(ctx *pulumi.Context, name string, a *Args, child pulumi.ResourceOption) (*truststoreBucket, error) {
	b := a.Truststore.NewBucket
	merged := map[string]string{}
	for k, v := range a.Tags {
		merged[k] = v
	}
	for k, v := range b.Tags {
		merged[k] = v
	}
	var tags pulumi.StringMapInput
	if len(merged) > 0 {
		tags = pulumi.ToStringMap(merged)
	}
	bucket, err := s3.NewBucket(ctx, name+"-truststore", &s3.BucketArgs{Bucket: pulumi.String(b.Name), Tags: tags},
		child, pulumi.Protect(true))
	if err != nil {
		return nil, fmt.Errorf("awsapigw truststore bucket: %w", err)
	}
	if _, err := s3.NewBucketServerSideEncryptionConfigurationV2(ctx, name+"-truststore-encryption",
		&s3.BucketServerSideEncryptionConfigurationV2Args{
			Bucket: bucket.ID(),
			Rules: s3.BucketServerSideEncryptionConfigurationV2RuleArray{
				&s3.BucketServerSideEncryptionConfigurationV2RuleArgs{
					ApplyServerSideEncryptionByDefault: &s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs{
						SseAlgorithm: pulumi.String("AES256"),
					},
				},
			},
		}, child); err != nil {
		return nil, err
	}
	versioning, err := s3.NewBucketVersioningV2(ctx, name+"-truststore-versioning", &s3.BucketVersioningV2Args{
		Bucket:                  bucket.ID(),
		VersioningConfiguration: &s3.BucketVersioningV2VersioningConfigurationArgs{Status: pulumi.String("Enabled")},
	}, child)
	if err != nil {
		return nil, err
	}
	block, err := s3.NewBucketPublicAccessBlock(ctx, name+"-truststore-public-access", &s3.BucketPublicAccessBlockArgs{
		Bucket: bucket.ID(), BlockPublicAcls: pulumi.Bool(true), BlockPublicPolicy: pulumi.Bool(true),
		IgnorePublicAcls: pulumi.Bool(true), RestrictPublicBuckets: pulumi.Bool(true),
	}, child)
	if err != nil {
		return nil, err
	}
	guard := a.guard(b.ApplyPrincipalArns)
	policy, err := s3.NewBucketPolicy(ctx, name+"-truststore-policy", &s3.BucketPolicyArgs{
		Bucket: bucket.ID(),
		Policy: bucket.Arn.ApplyT(func(arn string) (string, error) {
			return jsonDocument([]map[string]any{{
				"Sid": "DenyPlainHTTP", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
				"Resource":  []string{arn, arn + "/*"},
				"Condition": map[string]any{"Bool": map[string]any{"aws:SecureTransport": "false"}},
			}, guard.Statement(arn)})
		}).(pulumi.StringOutput),
	}, child, pulumi.DependsOn([]pulumi.Resource{block}))
	if err != nil {
		return nil, err
	}
	return &truststoreBucket{bucket: bucket, ready: []pulumi.Resource{versioning, policy}}, nil
}
