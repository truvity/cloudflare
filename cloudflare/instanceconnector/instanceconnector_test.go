package instanceconnector_test

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v4/cloudflare/cloudflared"
	"github.com/truvity/edge/v4/cloudflare/instanceconnector"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

func args(arch string) instanceconnector.Args {
	return instanceconnector.Args{
		Arch:           arch,
		TokenParameter: "/example/estate/tunnel-token",
		Region:         "eu-west-1",
	}
}

func render(f instanceconnector.Fragment) string {
	var b strings.Builder
	for _, s := range []struct{ name, body string }{
		{"Install", f.Install}, {"Unit (" + f.UnitPath + ")", f.Unit}, {"LoadToken", f.LoadToken}, {"Start", f.Start},
	} {
		b.WriteString("##### " + s.name + "\n" + s.body + "\n")
	}
	b.WriteString("##### SSMParameters\n" + strings.Join(f.SSMParameters, "\n") + "\n")
	return b.String()
}

func TestGolden(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			f, err := instanceconnector.Bootstrap(args(arch))
			require.NoError(t, err)
			got := render(f)
			golden := filepath.Join("testdata", "bootstrap-"+arch+".golden")
			if *update {
				require.NoError(t, os.WriteFile(golden, []byte(got), 0o644))
			}
			want, err := os.ReadFile(golden)
			require.NoError(t, err)
			assert.Equal(t, string(want), got, "go test ./cloudflare/instanceconnector -update, then review the diff")
		})
	}
}

func TestPinnedChecksumPerArch(t *testing.T) {
	for arch, sum := range map[string]string{"amd64": cloudflared.SHA256AMD64, "arm64": cloudflared.SHA256ARM64} {
		f, err := instanceconnector.Bootstrap(args(arch))
		require.NoError(t, err)
		assert.Contains(t, f.Install, sum)
		assert.Contains(t, f.Install, cloudflared.BinaryURL(arch))
		assert.NotContains(t, f.Install, "latest")
	}
}

// TestUnitMatchesStatusbox: the unit this package renders behaves like the one
// statusbox runs today (ExecStart flags, restart policy, user, hardening, the
// token env file), given the same arguments.
func TestUnitMatchesStatusbox(t *testing.T) {
	raw, err := os.ReadFile("testdata/statusbox-cloudflared.service")
	require.NoError(t, err)
	_, theirs, ok := strings.Cut(string(raw), "\n---\n")
	require.True(t, ok)

	a := args("amd64")
	a.User = "statusbox"
	a.EnvFile = "/run/statusbox/tunnel.env"
	f, err := instanceconnector.Bootstrap(a)
	require.NoError(t, err)

	normalise := func(s string) string {
		var out []string
		for _, l := range strings.Split(s, "\n") {
			if strings.HasPrefix(l, "Description=") || l == "EnvironmentFile=/etc/statusbox/common.env" {
				continue
			}
			out = append(out, l)
		}
		return strings.Join(out, "\n")
	}
	assert.Equal(t, normalise(theirs), normalise(f.Unit))
}

func TestDefaultsAndOptions(t *testing.T) {
	f, err := instanceconnector.Bootstrap(args("arm64"))
	require.NoError(t, err)
	assert.Equal(t, "/etc/systemd/system/cloudflared.service", f.UnitPath)
	assert.Contains(t, f.Unit, "User=cloudflared\n")
	assert.Contains(t, f.Unit, "EnvironmentFile=/run/cloudflared/tunnel.env\n")
	assert.Contains(t, f.Unit, "ExecStart=/usr/local/bin/cloudflared --no-autoupdate tunnel run\n")
	assert.NotContains(t, f.Unit, "[Install]")
	assert.Contains(t, f.Start, "systemctl start cloudflared.service")
	assert.Equal(t, []string{"/example/estate/tunnel-token"}, f.SSMParameters)

	a := args("arm64")
	a.EnableOnBoot = true
	a.UnitName = "edge-tunnel"
	a.BinDir = "/opt/bin"
	g, err := instanceconnector.Bootstrap(a)
	require.NoError(t, err)
	assert.Contains(t, g.Unit, "[Install]\nWantedBy=multi-user.target\n")
	assert.Contains(t, g.Unit, "ExecStart=/opt/bin/cloudflared ")
	assert.Contains(t, g.Unit, "EnvironmentFile=/run/edge-tunnel/tunnel.env\n")
	assert.Contains(t, g.Start, "systemctl enable --now edge-tunnel.service")
}

func TestLoadTokenNeverCarriesASecret(t *testing.T) {
	f, err := instanceconnector.Bootstrap(args("amd64"))
	require.NoError(t, err)
	assert.Contains(t, f.LoadToken, "--with-decryption")
	assert.Contains(t, f.LoadToken, "umask 077")
	assert.Contains(t, f.LoadToken, "chmod 0600")
	// The value is only ever expanded into the file, never into echo/log output.
	assert.NotRegexp(t, `echo[^\n]*\$value`, f.LoadToken)
	assert.NotRegexp(t, `(?m)^[^#\n]*printf[^\n]*\$value[^\n]*>&2`, f.LoadToken)
}

func TestValidation(t *testing.T) {
	cases := map[string]func(*instanceconnector.Args){
		"Arch":                 func(a *instanceconnector.Args) { a.Arch = "x86_64" },
		"TokenParameter":       func(a *instanceconnector.Args) { a.TokenParameter = "relative/name" },
		"TokenParameter ..":    func(a *instanceconnector.Args) { a.TokenParameter = "/a/../b" },
		"TokenParameter quote": func(a *instanceconnector.Args) { a.TokenParameter = "/a';rm -rf /;'" },
		"Region":               func(a *instanceconnector.Args) { a.Region = "" },
		"User":                 func(a *instanceconnector.Args) { a.User = "Root User" },
		"BinDir":               func(a *instanceconnector.Args) { a.BinDir = "bin" },
		"BinDir space":         func(a *instanceconnector.Args) { a.BinDir = "/opt/my bin" },
		"UnitName":             func(a *instanceconnector.Args) { a.UnitName = "x.service" },
		"EnvFile":              func(a *instanceconnector.Args) { a.EnvFile = "/etc/tunnel.env" },
		"EnvFile in /run":      func(a *instanceconnector.Args) { a.EnvFile = "/run/tunnel.env" },
		"EnvFile ..":           func(a *instanceconnector.Args) { a.EnvFile = "/run/x/../../etc/tunnel.env" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := args("amd64")
			mutate(&a)
			_, err := instanceconnector.Bootstrap(a)
			require.Error(t, err)
		})
	}
	_, err := instanceconnector.Bootstrap(instanceconnector.Args{})
	require.Error(t, err)
}

func TestRenderedShellParses(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		f, err := instanceconnector.Bootstrap(args(arch))
		require.NoError(t, err)
		script := "set -euo pipefail\n" + f.Install + f.LoadToken + f.Start
		cmd := exec.Command("bash", "-n")
		cmd.Stdin = strings.NewReader(script)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))

		if sc, lookErr := exec.LookPath("shellcheck"); lookErr == nil {
			cmd := exec.Command(sc, "-s", "bash", "-")
			cmd.Stdin = strings.NewReader("#!/usr/bin/env bash\n" + script)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, string(out))
		} else {
			t.Log("shellcheck not on PATH; only bash -n ran")
		}
	}
}

// TestLoadTokenRuns executes LoadToken against a fake aws and checks the file
// it writes: mode, content, and that nothing reaches stdout or stderr.
func TestLoadTokenRuns(t *testing.T) {
	dir := t.TempDir()
	fakeBin := filepath.Join(dir, "bin")
	require.NoError(t, os.MkdirAll(fakeBin, 0o755))
	fake := "#!/bin/sh\nprintf '%s' 'sec\"ret\\tok'\n"
	require.NoError(t, os.WriteFile(filepath.Join(fakeBin, "aws"), []byte(fake), 0o755))

	f, err := instanceconnector.Bootstrap(args("amd64"))
	require.NoError(t, err)
	// The real EnvFile must be under /run; redirect it into the temp dir for the run.
	script := strings.ReplaceAll(f.LoadToken, "/run/cloudflared", dir+"/run")
	cmd := exec.Command("bash", "-c", "set -euo pipefail\n"+script)
	cmd.Env = append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(t, cmd.Run(), stderr.String())
	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())

	file := filepath.Join(dir, "run", "tunnel.env")
	st, err := os.Stat(file)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	body, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.Equal(t, "TUNNEL_TOKEN=\"sec\\\"ret\\\\tok\"\n", string(body))
}

func TestNoNonStdlibImports(t *testing.T) {
	const pkg = "github.com/truvity/edge/v4/cloudflare/instanceconnector"

	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	require.NoError(t, err, "go list -deps")

	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || line == pkg || line == "github.com/truvity/edge/v4/cloudflare/cloudflared" {
			continue
		}
		root, _, _ := strings.Cut(line, "/")
		assert.NotContains(t, root, ".", "cloudflare/instanceconnector must depend on the standard library and cloudflare/cloudflared only, found %q", line)
	}
}
