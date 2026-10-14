// Package cloudflared is the one place the estate's cloudflared version is
// pinned: the container image the chart runs and the linux binaries an
// instance installs. It imports the standard library only.
//
// Everything here is rewritten together by hack/cloudflared-pin.sh from the
// upstream release; `hack/cloudflared-pin.sh check` (part of `just lint`)
// fails when charts/cloudflared/values.yaml disagrees.
package cloudflared

// Version is the cloudflared release, as upstream tags it and as the
// container image tag spells it.
const Version = "2026.10.0"

// ImageRepository is the container image repository.
const ImageRepository = "cloudflare/cloudflared"

// ImageDigest is the digest of the multi-architecture image index for Version
// on Docker Hub. The chart references the image by tag, which is the form it
// had before this pin; the digest is for callers that pin by digest.
const ImageDigest = "sha256:9b49eed8f62806d5d45ddf59ecefb5710429598ea6d3fcccd2af938f621b2b07"

// SHA256AMD64 and SHA256ARM64 are the sha256 of the release assets
// cloudflared-linux-amd64 and cloudflared-linux-arm64, as upstream publishes
// them with the release.
const (
	SHA256AMD64 = "d33ff2d14475178d2012c2c56beba87389ac5ded27649519f198a7d3134a99db"
	SHA256ARM64 = "e6422b9d4f72d3194bc5a38676f13667c06666523217b842a877d72a80b5ac08"
)

// BinaryURL is the download URL of the linux binary for arch ("amd64" or
// "arm64") at Version.
func BinaryURL(arch string) string {
	return "https://github.com/cloudflare/cloudflared/releases/download/" + Version + "/cloudflared-linux-" + arch
}

// BinarySHA256 returns the pinned sha256 of the linux binary for arch
// ("amd64" or "arm64"), and false for any other architecture.
func BinarySHA256(arch string) (string, bool) {
	switch arch {
	case "amd64":
		return SHA256AMD64, true
	case "arm64":
		return SHA256ARM64, true
	}
	return "", false
}
