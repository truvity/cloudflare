# cloudflare/awsapigw

The AWS API Gateway front door behind Cloudflare. An HTTP API is reachable
only through Cloudflare: its custom domain demands a client certificate, and
the only certificate it trusts is Cloudflare's origin-pull CA. Everything
else fails the TLS handshake.

```go
d, err := awsapigw.New(ctx, "edge", &awsapigw.Args{
	FrontDoor:     awsapigw.FrontDoor{APIID: apiID, StageName: stage},
	DomainName:    "api.example.com",
	TruststorePEM: originPullCAPEM, // Cloudflare's Authenticated Origin Pulls CA
	Truststore: awsapigw.Truststore{NewBucket: &awsapigw.NewBucketArgs{
		Name: "example-truststore", ApplyPrincipalArns: applyRoleARNs,
	}},
	Certificate: &awsapigw.CertificateArgs{CreateValidationRecord: createRecord},
	DNS: &awsapigw.DNSArgs{Provider: cf, ZoneID: zoneID, Proxied: true},
}, pulumi.Provider(awsProvider))
```

## What it creates

| Resource (logical name) | Notes |
|---|---|
| `<name>-certificate`, `<name>-certificate-validation` | Only with `Certificate`: an ACM certificate with DNS validation. The record is made by your callback, so the package holds no DNS credential. With `CertificateArn` you bring the certificate. |
| `<name>-truststore`, `-truststore-encryption`, `-truststore-versioning`, `-truststore-public-access`, `-truststore-policy` | Only with `Truststore.NewBucket`: a protected, encrypted, versioned, private bucket whose policy denies plain HTTP and denies writes under `truststore/` to everyone but `ApplyPrincipalArns`. |
| `<name>-truststore-pem` | The one object, `truststore/client-ca.pem`. The domain pins its version. |
| `<name>-domain` | Regional, TLS 1.2, mutual TLS on the truststore. |
| `<name>-domain-mapping` | The domain to `APIID` / `StageName`. |
| `Args.DNS.ResourceName` (default `<name>-dns`) | Only with `DNS`: the CNAME of the domain to the API Gateway target, made with your Cloudflare provider. |

The logical names are a contract: a stack that has them keeps its resources.
A test pins the set.

## Authenticated Origin Pulls

The package does not turn on the zone setting. Set `tls_client_auth` on the
zone (`cloudflare/zone`: `AuthenticatedOriginPulls`), and the record must be
proxied (`DNS.Proxied`), or Cloudflare presents no client certificate and the
domain refuses every request. Keep the API's default `execute-api` endpoint
disabled: it does not ask for a client certificate.

## The truststore and its guard

API Gateway reads the truststore from S3 and pins an object version. Whoever
can write that object chooses who may call the API, so the prefix is guarded:
a bucket policy statement (`ProtectedPrefix.Statement`) denies writes under
`truststore/` to every principal whose ARN is not in the apply list (the CD
role, an admin role, a break-glass role; roles, never sessions).

- `Truststore.NewBucket` builds a bucket with that guard.
- `Truststore.Existing{BucketName, Versioned, GuardedPrefix}` uses a bucket you
  own. The package cannot see its configuration, so you attest that it is
  versioned and carries the guard (put `ProtectedPrefix{...}.Statement(bucketARN)`
  in its policy), and it refuses an attestation that is not given.

## DNS ownership

DNS is yours unless you pass `DNS`. Without it, point `DomainName` at
`Domain.DomainTarget` (a CNAME) yourself. With it, the record is created with
`DNS.Provider` in `DNS.ZoneID`. To take over a record the stack already has, set
`ResourceName` to its logical name and, if its URN differs, `Aliases`.

## Migrating from sluis

`truvity/sluis` `deploy/pulumi/edge/cloudflare` (`edgecloudflare.NewEdge`)
registered the same resources under the same names. To move without
replacing anything:

1. Build `FrontDoor` from sluis's `Lambda.FrontDoor()` by copying its fields
   (`Name`, `Component`, `APIID`, `StageName`); there is no sluis import. The
   domain and mapping are aliased to `<FrontDoor.Name>-domain` and
   `<FrontDoor.Name>-domain-mapping` under `FrontDoor.Component`, as sluis did.
2. Keep the component's type: pass `ComponentType: awsapigw.ComponentTypeSluis`
   (`sluis:aws:CloudflareEdge`) so the URN is unchanged, with no reliance on
   alias inheritance. Or leave the default
   (`truvity:aws:ApiGatewayDomain`) and pass
   `pulumi.Aliases([]pulumi.Alias{{Type: pulumi.String("sluis:aws:CloudflareEdge")}})`
   as an option to `New`; Pulumi then renames the component and its children.
3. A sluis `Storage` becomes `Truststore.Existing{BucketName, Versioned: true,
   GuardedPrefix: true}` (sluis checked these on the object; now you attest
   them). A sluis `TruststoreBucket` becomes `Truststore.NewBucket`.
4. `PublicCache` (the Cloudflare cache rule) is not part of this package; the
   zone's `public_cache` contribution does it.
5. Run the preview: it must show no replace.
