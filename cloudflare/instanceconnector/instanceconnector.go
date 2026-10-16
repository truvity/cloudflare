// Package instanceconnector renders the shell and the systemd unit that run
// the pinned cloudflared (cloudflare/cloudflared) as a tunnel connector on a
// Linux instance, with the tunnel token read from SSM Parameter Store at boot.
//
// Bootstrap returns a Fragment in pieces, so a caller can install early and
// start late: statusbox installs and writes the unit at first boot and starts
// cloudflared only after its Litestream restore. The pieces are bash source
// for the caller's own script; the shell pieces are bash, work with or
// without `set -e`, and fail with a non-zero status and a reason on stderr:
//
//	Install    download the pinned binary, verify its sha256, install it
//	Unit       the systemd unit file text, to be written to UnitPath
//	LoadToken  SSM -> an env file under /run, mode 0600; never echoed
//	Start      daemon-reload, then enable (if asked) and start the unit
//
// The token is never in the fragment, in user-data or in any log line: only
// the SSM parameter name is.
//
// The package imports the standard library only.
package instanceconnector

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/truvity/edge/v4/cloudflare/cloudflared"
)

// Defaults applied by Bootstrap to a zero field.
const (
	DefaultUser     = "cloudflared"
	DefaultBinDir   = "/usr/local/bin"
	DefaultUnitName = "cloudflared"
)

// Args is what Bootstrap needs.
type Args struct {
	// Arch is the instance's CPU architecture: "amd64" or "arm64". Required.
	Arch string
	// TokenParameter is the SSM parameter holding the tunnel token (a
	// SecureString), an absolute name like /my/estate/tunnel-token. Required.
	// The instance role needs ssm:GetParameter on it (and kms:Decrypt on its
	// key); Fragment.SSMParameters lists it for building that policy.
	TokenParameter string
	// Region is the AWS region of the parameter. Required.
	Region string
	// User is the system user the unit runs as. It must already exist (the
	// caller creates it). Default DefaultUser.
	User string
	// BinDir is where the binary is installed, as BinDir/cloudflared.
	// Absolute. Default DefaultBinDir.
	BinDir string
	// UnitName is the systemd unit name without ".service". Default
	// DefaultUnitName.
	UnitName string
	// EnvFile is the file holding TUNNEL_TOKEN="...". Absolute, in a
	// directory below /run (tmpfs, so it never reaches the disk). Default
	// /run/<UnitName>/tunnel.env.
	EnvFile string
	// EnableOnBoot adds an [Install] section (WantedBy=multi-user.target) and
	// makes Start run `systemctl enable --now`. Leave false when the caller
	// starts the unit itself every boot, after LoadToken, as the token file
	// in /run does not survive a reboot.
	EnableOnBoot bool
}

// Fragment is the rendered connector, in pieces.
type Fragment struct {
	// Install is idempotent bash: a binary already at the pinned checksum is
	// left alone; otherwise the pinned release asset is downloaded, checked
	// with sha256sum -c and installed (mode 0755). Needs curl, sha256sum, install.
	Install string
	// Unit is the systemd unit file text; write it to UnitPath.
	Unit string
	// UnitPath is /etc/systemd/system/<UnitName>.service.
	UnitPath string
	// LoadToken is bash: it reads TokenParameter with the aws CLI
	// (--with-decryption) and writes TUNNEL_TOKEN into EnvFile, mode 0600,
	// directory mode 0700. Needs the aws CLI and the instance role.
	LoadToken string
	// Start is bash: systemctl daemon-reload, then start (or enable --now).
	Start string
	// SSMParameters lists the parameter names the fragment reads, for the
	// instance role's policy.
	SSMParameters []string
}

var (
	pathRe   = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
	paramRe  = regexp.MustCompile(`^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`)
	regionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	userRe   = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	unitRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)
)

// Bootstrap validates a, applies the defaults and renders the fragment.
func Bootstrap(a Args) (Fragment, error) {
	if a.User == "" {
		a.User = DefaultUser
	}
	if a.BinDir == "" {
		a.BinDir = DefaultBinDir
	}
	if a.UnitName == "" {
		a.UnitName = DefaultUnitName
	}
	if a.EnvFile == "" && unitRe.MatchString(a.UnitName) {
		a.EnvFile = "/run/" + a.UnitName + "/tunnel.env"
	}
	if err := a.validate(); err != nil {
		return Fragment{}, err
	}
	sum, _ := cloudflared.BinarySHA256(a.Arch)

	return Fragment{
		Install:       a.install(sum),
		Unit:          a.unit(),
		UnitPath:      "/etc/systemd/system/" + a.UnitName + ".service",
		LoadToken:     a.loadToken(),
		Start:         a.start(),
		SSMParameters: []string{a.TokenParameter},
	}, nil
}

func (a Args) validate() error {
	var errs []error
	if _, ok := cloudflared.BinarySHA256(a.Arch); !ok {
		errs = append(errs, fmt.Errorf("args.Arch %q: want amd64 or arm64", a.Arch))
	}
	if !paramRe.MatchString(a.TokenParameter) || strings.Contains(a.TokenParameter, "..") {
		errs = append(errs, fmt.Errorf("args.TokenParameter %q: want an absolute SSM parameter name like /estate/tunnel-token", a.TokenParameter))
	}
	if !regionRe.MatchString(a.Region) {
		errs = append(errs, fmt.Errorf("args.Region %q: want an AWS region like eu-west-1", a.Region))
	}
	if !userRe.MatchString(a.User) {
		errs = append(errs, fmt.Errorf("args.User %q: not a valid system user name", a.User))
	}
	if !safePath(a.BinDir) {
		errs = append(errs, fmt.Errorf("args.BinDir %q: want an absolute path of letters, digits and _ . / -", a.BinDir))
	}
	if !unitRe.MatchString(a.UnitName) {
		errs = append(errs, fmt.Errorf("args.UnitName %q: want a plain unit name without the .service suffix", a.UnitName))
	}
	if !safePath(a.EnvFile) || !strings.HasPrefix(a.EnvFile, "/run/") || strings.Count(a.EnvFile, "/") < 3 || strings.HasSuffix(a.EnvFile, "/") {
		errs = append(errs, fmt.Errorf("args.EnvFile %q: want a file in a directory below /run, like /run/cloudflared/tunnel.env", a.EnvFile))
	}
	return errors.Join(errs...)
}

// safePath reports whether p is absolute, made of characters no shell or
// systemd quoting can mangle, and free of "." and ".." elements.
func safePath(p string) bool {
	if !pathRe.MatchString(p) {
		return false
	}
	for _, el := range strings.Split(p, "/") {
		if el == "." || el == ".." {
			return false
		}
	}
	return !strings.Contains(p, "//")
}

func (a Args) envDir() string {
	return a.EnvFile[:strings.LastIndex(a.EnvFile, "/")]
}

func (a Args) binary() string { return a.BinDir + "/cloudflared" }

func (a Args) install(sum string) string {
	return fmt.Sprintf(`# cloudflared %[1]s linux-%[2]s: installed to %[3]s, checksum pinned in cloudflare/cloudflared.
cloudflared_install() {
  local want=%[4]s url=%[5]s dest=%[3]s tmp i
  if [ -x "$dest" ] && [ "$(sha256sum "$dest" | cut -d' ' -f1)" = "$want" ]; then
    return 0
  fi
  tmp="$(mktemp -d)" || return 1
  for i in 1 2 3 4 5; do
    if curl -fsSL --connect-timeout 10 --max-time 300 -o "$tmp/cloudflared" "$url" \
      && printf '%%s  %%s\n' "$want" "$tmp/cloudflared" | sha256sum -c - >/dev/null 2>&1; then
      install -d -m 0755 %[6]s || { rm -rf "$tmp"; return 1; }
      install -m 0755 "$tmp/cloudflared" "$dest" || { rm -rf "$tmp"; return 1; }
      rm -rf "$tmp"
      return 0
    fi
    echo "cloudflared: download of $url failed or did not match its checksum (attempt $i)" >&2
    rm -f "$tmp/cloudflared"
    sleep "${CLOUDFLARED_RETRY_SLEEP:-5}"
  done
  rm -rf "$tmp"
  return 1
}
cloudflared_install
`, cloudflared.Version, a.Arch, a.binary(), sq(sum), sq(cloudflared.BinaryURL(a.Arch)), sq(a.BinDir))
}

func (a Args) unit() string {
	var b strings.Builder
	fmt.Fprintf(&b, `[Unit]
Description=cloudflared tunnel (%s)
After=network-online.target
Wants=network-online.target

[Service]
User=%s
Group=%s
EnvironmentFile=%s
ExecStart=%s --no-autoupdate tunnel run
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
`, a.UnitName, a.User, a.User, a.EnvFile, a.binary())
	if a.EnableOnBoot {
		b.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	}
	return b.String()
}

func (a Args) loadToken() string {
	return fmt.Sprintf(`# The tunnel token goes from SSM to %[1]s (tmpfs); it is never printed.
cloudflared_load_token() {
  local param=%[2]s envfile=%[1]s value i
  mkdir -p %[3]s && chmod 0700 %[3]s || return 1
  for i in 1 2 3 4 5 6; do
    if value="$(aws ssm get-parameter --name "$param" --with-decryption --query Parameter.Value --output text --region %[4]s)"; then
      break
    fi
    value=""
    [ "$i" = 6 ] || sleep "${CLOUDFLARED_RETRY_SLEEP:-5}"
  done
  if [ -z "$value" ] || [ "$value" = None ]; then
    echo "cloudflared: could not read SSM parameter $param" >&2
    return 1
  fi
  case "$value" in
    *$'\n'*) echo "cloudflared: the value of $param contains a newline" >&2; value=""; return 1 ;;
  esac
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  (umask 077 && printf 'TUNNEL_TOKEN="%%s"\n' "$value" >"$envfile.part") || { value=""; return 1; }
  value=""
  chmod 0600 "$envfile.part" && mv "$envfile.part" "$envfile"
}
cloudflared_load_token
`, a.EnvFile, sq(a.TokenParameter), sq(a.envDir()), sq(a.Region))
}

func (a Args) start() string {
	verb := "start"
	if a.EnableOnBoot {
		verb = "enable --now"
	}
	return fmt.Sprintf("systemctl daemon-reload\nsystemctl %s %s.service\n", verb, a.UnitName)
}

// sq single-quotes s for bash. Every value reaching it has already passed a
// validator that admits no quote, so this is belt and braces.
func sq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
