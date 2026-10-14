#!/usr/bin/env bash
# One cloudflared version for the whole estate. The Go package
# cloudflare/cloudflared and charts/cloudflared/values.yaml must name the same
# release; this script is the only writer of both, and CI runs `check`.
#
#   hack/cloudflared-pin.sh <version>   fetch the release's checksums and the
#                                       image digest, rewrite the Go pin and
#                                       the chart value (then: just golden)
#   hack/cloudflared-pin.sh check       fail when the chart value differs from
#                                       the Go pin
#
# Needs: gh (authenticated), curl, python3 for <version>; check needs only sh tools.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
gofile="$root/cloudflare/cloudflared/cloudflared.go"
values="$root/charts/cloudflared/values.yaml"

go_const() { sed -n "s/^const $1 = \"\\(.*\\)\"\$/\\1/p" "$gofile"; }
go_group() { sed -n "s/^[[:space:]]*$1 = \"\\(.*\\)\"\$/\\1/p" "$gofile"; }
chart_tag() { sed -n 's/^  tag: "\(.*\)".*$/\1/p' "$values"; }

if [ "${1:-}" = check ]; then
  pin="$(go_const Version)"
  tag="$(chart_tag)"
  if [ -z "$pin" ] || [ "$pin" != "$tag" ]; then
    echo "cloudflared: charts/cloudflared/values.yaml image.tag '$tag' != cloudflare/cloudflared Version '$pin' (run hack/cloudflared-pin.sh <version>)" >&2
    exit 1
  fi
  exit 0
fi

version="${1:?usage: hack/cloudflared-pin.sh <version>|check}"
case "$version" in
  [0-9][0-9][0-9][0-9].[0-9]*.[0-9]*) ;;
  *) echo "cloudflared: '$version' is not a release like 2026.10.0" >&2; exit 2 ;;
esac

# The asset digests GitHub computed at upload. The release notes carry the
# upstream's own checksum list; the two must agree.
assets="$(gh release view "$version" --repo cloudflare/cloudflared --json assets,body)"
sum() {
  ASSETS="$assets" python3 -I -c '
import json, os, re, sys
d = json.loads(os.environ["ASSETS"]); name = sys.argv[1]
asset = [a["digest"].removeprefix("sha256:") for a in d["assets"] if a["name"] == name]
note = re.findall(r"^" + re.escape(name) + r": ([0-9a-f]{64})$", d["body"], re.M)
if len(asset) != 1 or len(note) != 1 or asset[0] != note[0]:
    sys.exit("cloudflared: no agreeing checksum for " + name)
print(asset[0])' "$1"
}
amd64="$(sum cloudflared-linux-amd64)"
arm64="$(sum cloudflared-linux-arm64)"

# The digest of the multi-arch image index on Docker Hub.
token="$(curl -fsS "https://auth.docker.io/token?service=registry.docker.io&scope=repository:cloudflare/cloudflared:pull" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
digest="$(curl -fsSI -H "Authorization: Bearer $token" \
  -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json" \
  "https://registry-1.docker.io/v2/cloudflare/cloudflared/manifests/$version" \
  | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p')"
case "$digest" in sha256:????????????????????????????????????????????????????????????????) ;; *) echo "cloudflared: no image digest for $version" >&2; exit 1 ;; esac

sed -i \
  -e "s|^const Version = \".*\"|const Version = \"$version\"|" \
  -e "s|^const ImageDigest = \".*\"|const ImageDigest = \"$digest\"|" \
  -e "s|^\\([[:space:]]*SHA256AMD64 = \\)\".*\"|\\1\"$amd64\"|" \
  -e "s|^\\([[:space:]]*SHA256ARM64 = \\)\".*\"|\\1\"$arm64\"|" \
  "$gofile"
sed -i "s|^\\(  tag: \\)\".*\"|\\1\"$version\"|" "$values"

echo "cloudflared pinned to $version (amd64 $amd64, arm64 $arm64, image $digest)"
echo "next: just golden, then describe the chart output change in CHANGELOG.md"
