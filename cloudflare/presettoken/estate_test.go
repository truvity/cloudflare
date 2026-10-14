package presettoken

import (
	"context"
	"slices"
	"testing"
	"time"
)

func testEstate() Estate {
	return Estate{
		SluisctlMin: testMin, BinaryPrefixes: []string{binDir}, Lifetime: time.Hour,
		GrantHint: "policy group example:deploy", Runbook: "docs/presets.md",
		BreakGlass: EstateBreakGlass{
			Env: testBreakGlassEnv, ItemEnv: testBreakGlassEnv + "_ITEM", Account: "example.1password.com", Vault: "vault",
			Field: "token", ChildPrefix: "example-breakglass", ItemHint: "accounts.%s.root_item in the registry",
		},
	}
}

func env(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }

// An account's configuration is the estate's plus its issuer and root item; the
// item is the account's, or the variable's for one command.
func TestEstateConfig(t *testing.T) {
	e := testEstate()

	conf, err := e.Config("one", "cf-root-one", testIssuer, env(nil))
	if err != nil {
		t.Fatal(err)
	}

	if err := conf.Validate(); err != nil {
		t.Fatal(err)
	}

	if conf.Issuer != testIssuer || conf.SluisctlMin != testMin || conf.Lifetime != time.Hour || conf.GrantHint == "" || conf.Runbook == "" {
		t.Errorf("estate fields lost: %+v", conf)
	}

	if got := conf.BreakGlass.Ref(); got != "op://vault/cf-root-one/token" {
		t.Errorf("ref %q", got)
	}

	conf, err = e.Config("one", "cf-root-one", testIssuer, env(map[string]string{testBreakGlassEnv + "_ITEM": "other"}))
	if err != nil || conf.BreakGlass.Ref() != "op://vault/other/token" {
		t.Errorf("the variable does not override: %v %q", err, conf.BreakGlass.Ref())
	}

	// No item: off is the zero block; on names what to set.
	conf, err = e.Config("one", "", testIssuer, env(nil))
	if err != nil || conf.BreakGlass != (BreakGlass{}) {
		t.Errorf("no item, off: %v %+v", err, conf.BreakGlass)
	}

	_, err = e.Config("one", "", testIssuer, env(map[string]string{testBreakGlassEnv: "1"}))
	if err == nil {
		t.Fatal("break-glass on without an item was accepted")
	}

	want := `break-glass for account "one": the 1Password item of its root token is not named: set ` +
		testBreakGlassEnv + `_ITEM=<item> for this command, or accounts.one.root_item in the registry`
	if err.Error() != want {
		t.Errorf("error %q, want %q", err, want)
	}

	// The estate's slice is not shared with the config.
	conf, _ = e.Config("one", "x", testIssuer, env(nil))
	conf.BinaryPrefixes[0] = "/changed"

	if !slices.Equal(e.BinaryPrefixes, []string{binDir}) {
		t.Error("Config shares the estate's BinaryPrefixes")
	}
}

func TestEstateCredential(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")

	f := &fakeCLI{sluisOut: `{"Version":1,"AccessKeyId":"AK","SecretAccessKey":"SK","Expiration":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}`}
	src := Source{Run: f.run, LookPath: nixPath, Now: func() time.Time { return now }}

	req := Request{Preset: "example-bucket", R2: true, AccountID: testAccount}

	cred, err := testEstate().Credential(context.Background(), src, "one", req, "cf-root-one", testIssuer, env(nil))
	if err != nil {
		t.Fatal(err)
	}

	if cred.AccessKeyID != "AK" || cred.SecretAccessKey != "SK" {
		t.Errorf("credential %+v", cred)
	}

	// An invalid estate is refused before anything runs.
	bad := testEstate()
	bad.BinaryPrefixes = nil

	calls := len(f.calls)
	if _, err := bad.Credential(context.Background(), src, "one", req, "cf-root-one", testIssuer, env(nil)); err == nil {
		t.Fatal("an estate with no binary prefix was accepted")
	}

	if len(f.calls) != calls {
		t.Error("a CLI ran for an invalid configuration")
	}
}
