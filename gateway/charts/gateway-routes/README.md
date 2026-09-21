# gateway-routes

One HTTPRoute whose rules are **named**, so a policy can attach to one of
them: `app` carries the gated surface (the shell, the API) and `static` the
public one (the content-hashed assets). A SecurityPolicy targets the route
with `sectionName: app`; every rule it does not name is served anonymously,
which is how an application's assets reach a browser that has not signed in
and an edge cache that holds no cookie.

A **library** chart: it renders nothing by itself. The application's own
chart depends on it and calls the template.

```yaml
# the application's Chart.yaml
dependencies:
  - name: gateway-routes
    version: 1.4.0
    repository: oci://ghcr.io/truvity/charts
```

```yaml
# the application's templates/httproute.yaml
{{ include "gateway-routes.productRoute" (dict "root" $ "route" .Values.route) }}
```

```yaml
# the application's values.yaml
route:
  name: example-app
  hostnames:
    - app.example
  parentRefs:
    - kind: ListenerSet
      name: example
      namespace: gateways
  backend:
    name: example-app
    port: 8080
  static:
    # Content-hashed file names: public, and cacheable to the extent the
    # origin's own Cache-Control says so.
    paths:
      - /app/assets
```

That renders one HTTPRoute with the rules `app` (`/`) and `static`
(`/app/assets`), both on `example-app:8080`. The estate then gates the
first of them, and only the first:

```yaml
# gateway-policies values, wherever the estate keeps them
securityPolicies:
  example-app:
    namespace: example
    targetRefs:
      - name: example-app
        sectionName: app
    oidc:
      clientID: example-app
      clientSecret: { name: example-app-client }
      hostname: app.example
```

Envoy matches the **most specific** path prefix, so `/app/assets` wins over
`app`'s `/` without ordering tricks: the rules can be read in any order and
mean the same thing.

- every input: [../../docs/reference.md](../../docs/reference.md#gateway-routes)
- every refusal and the traps: [../../docs/safety.md](../../docs/safety.md#gateway-routes)
- why the split lives in one object: [../../docs/doctrine.md](../../docs/doctrine.md)
