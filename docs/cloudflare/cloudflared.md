# One cloudflared version, and the instance connector

Two packages and one script keep every cloudflared in an estate on the same
release, whether it runs in a cluster or on a plain instance.

## The pin: `cloudflare/cloudflared`

Standard library only. It exports:

| Symbol | Meaning |
|---|---|
| `Version` | The release, as upstream tags it and as the image tag spells it. |
| `ImageRepository`, `ImageDigest` | The container image and the digest of its multi-architecture index. The chart references the image by tag; the digest is for callers that pin by digest. |
| `SHA256AMD64`, `SHA256ARM64` | sha256 of the release assets `cloudflared-linux-amd64` and `cloudflared-linux-arm64`. |
| `BinaryURL(arch)`, `BinarySHA256(arch)` | The download URL and the checksum for `amd64` or `arm64`. |

`charts/cloudflared/values.yaml` (`image.tag`) must equal `Version`. A Go test
and `hack/cloudflared-pin.sh check` (part of `just lint`) fail when they differ.

### Bumping the pin

```
hack/cloudflared-pin.sh 2026.10.0
just golden        # the chart's rendered image changes; review the diff
```

The script reads the release with `gh release view`, takes each checksum from
the asset digest GitHub computed at upload and refuses it unless it equals the
checksum in the release notes, reads the image index digest from Docker Hub,
and rewrites `cloudflare/cloudflared/cloudflared.go` and the chart value. Then
describe the chart output change in `CHANGELOG.md`: a consumer's zero-diff
gate shows the new image tag once it moves to the new chart version.

## The connector: `cloudflare/instanceconnector`

Standard library plus `cloudflare/cloudflared`. `Bootstrap(Args)` renders the
shell and the systemd unit that run the pinned cloudflared on a Linux
instance, with the tunnel token read from SSM at boot. It returns a `Fragment`
in pieces so a caller can install early and start late (statusbox starts
cloudflared after its Litestream restore).

```go
f, err := instanceconnector.Bootstrap(instanceconnector.Args{
    Arch:           "arm64",
    TokenParameter: "/example/estate/tunnel-token",
    Region:         "eu-west-1",
})
```

| `Args` field | Default | Meaning |
|---|---|---|
| `Arch` | required | `amd64` or `arm64`. |
| `TokenParameter` | required | Absolute SSM parameter name of the token (SecureString). |
| `Region` | required | AWS region of the parameter. |
| `User` | `cloudflared` | System user of the unit; it must exist. |
| `BinDir` | `/usr/local/bin` | The binary is `BinDir/cloudflared`. |
| `UnitName` | `cloudflared` | Unit name without `.service`. |
| `EnvFile` | `/run/<UnitName>/tunnel.env` | Token env file; must be in a directory below `/run`. |
| `EnableOnBoot` | false | Adds `[Install]` and makes `Start` run `enable --now`. |

| `Fragment` field | What it is |
|---|---|
| `Install` | Idempotent bash: leaves a binary already at the pinned checksum alone; else downloads the pinned asset, `sha256sum -c`, `install -m 0755`. |
| `Unit`, `UnitPath` | The unit file text and `/etc/systemd/system/<UnitName>.service`. Write one to the other. |
| `LoadToken` | Bash: `aws ssm get-parameter --with-decryption` into `TUNNEL_TOKEN="..."` in `EnvFile`, mode 0600, directory 0700, written atomically; the value is never printed. |
| `Start` | `systemctl daemon-reload`, then `start` (or `enable --now`). |
| `SSMParameters` | The parameter names read, for the instance role's policy (`ssm:GetParameter`, and `kms:Decrypt` on the key). |

The unit behaves like the one statusbox runs: `cloudflared --no-autoupdate
tunnel run`, `Restart=always`, `RestartSec=5`, `NoNewPrivileges`,
`PrivateTmp`, the token only through `EnvironmentFile`. Tests compare it with
a copy of that unit. The token is never in the fragment or in user-data; only
the parameter name is. The env file lives on tmpfs and does not survive a
reboot, so a caller that starts the unit on every boot runs `LoadToken` first
each time.

Invalid input (unknown arch, a relative or odd parameter name, a region that
is not a region, paths with spaces or `..`, an env file outside `/run`) is an
error from `Bootstrap`, with every problem listed.
