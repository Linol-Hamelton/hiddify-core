package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// The Dart client serialises SingboxRule with FieldRename.kebab, so the Go
// side has to accept and emit those exact keys.
func TestRuleProcessFieldsUseKebabKeys(t *testing.T) {
	const input = `{"process-name":["curl.exe"],"process-path":["C:\\bin\\curl.exe"],"outbound":"bypass"}`

	var rule Rule
	if err := json.Unmarshal([]byte(input), &rule); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := rule.ProcessName; !reflect.DeepEqual(got, []string{"curl.exe"}) {
		t.Errorf("ProcessName = %#v", got)
	}
	if got := rule.ProcessPath; !reflect.DeepEqual(got, []string{`C:\bin\curl.exe`}) {
		t.Errorf("ProcessPath = %#v", got)
	}

	encoded, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"process-name"`, `"process-path"`} {
		if !strings.Contains(string(encoded), key) {
			t.Errorf("key %s missing from %s", key, encoded)
		}
	}
	for _, key := range []string{`"process_name"`, `"processName"`} {
		if strings.Contains(string(encoded), key) {
			t.Errorf("unexpected key %s in %s", key, encoded)
		}
	}
}

// A config written before the process fields existed has to round-trip
// unchanged, so both keys are omitempty.
func TestRuleWithoutProcessFieldsOmitsBothKeys(t *testing.T) {
	encoded, err := json.Marshal(Rule{Domains: "example.com", Outbound: "proxy"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "process-") {
		t.Errorf("process key leaked into %s", encoded)
	}
}

// tcpAndUdp is the empty string on the Dart side and must not reach the
// generated config as a network match.
func TestMakeRuleOmitsNetworkForTcpAndUdp(t *testing.T) {
	encoded, err := json.Marshal((&Rule{Network: "", ProcessName: []string{"curl.exe"}}).MakeRule())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), `"network"`) {
		t.Errorf("network key present in %s", encoded)
	}
}

func TestMakeRuleCarriesProcessFields(t *testing.T) {
	rule := (&Rule{
		ProcessName: []string{"curl.exe"},
		ProcessPath: []string{`C:\bin\curl.exe`},
	}).MakeRule()

	if !reflect.DeepEqual([]string(rule.ProcessName), []string{"curl.exe"}) {
		t.Errorf("ProcessName = %#v", rule.ProcessName)
	}
	if !reflect.DeepEqual([]string(rule.ProcessPath), []string{`C:\bin\curl.exe`}) {
		t.Errorf("ProcessPath = %#v", rule.ProcessPath)
	}
	// A process-only rule must survive the IsValid filter in the rules loop.
	if !rule.IsValid() {
		t.Error("process-only rule rejected by IsValid")
	}
}

func TestHasRuleHelpers(t *testing.T) {
	for _, tc := range []struct {
		name            string
		rule            Rule
		domain, process bool
	}{
		{"empty", Rule{}, false, false},
		{"domain only", Rule{Domains: "example.com"}, true, false},
		{"name only", Rule{ProcessName: []string{"curl.exe"}}, false, true},
		{"path only", Rule{ProcessPath: []string{`C:\bin\curl.exe`}}, false, true},
		{"ip only", Rule{IP: "1.1.1.1"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.HasDomainRule(); got != tc.domain {
				t.Errorf("HasDomainRule = %v, want %v", got, tc.domain)
			}
			if got := tc.rule.HasProcessRule(); got != tc.process {
				t.Errorf("HasProcessRule = %v, want %v", got, tc.process)
			}
		})
	}
}

func routingOptions(t *testing.T, opt HiddifyOptions) *option.Options {
	t.Helper()
	options := &option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(options, &opt); err != nil {
		t.Fatalf("setRoutingOptions: %v", err)
	}
	return options
}

func TestProcessRuleRoutesWithoutDerivingDNSRule(t *testing.T) {
	base := HiddifyOptions{DNSOptions: DNSOptions{EnableDNSRouting: true}}
	withProcess := base
	withProcess.Rules = []Rule{{ProcessPath: []string{`C:\bin\curl.exe`}, Outbound: "bypass"}}

	baseline := routingOptions(t, base)
	got := routingOptions(t, withProcess)

	// The process rule reaches the router,
	var found bool
	for _, rule := range got.Route.Rules {
		if reflect.DeepEqual([]string(rule.DefaultOptions.ProcessPath), []string{`C:\bin\curl.exe`}) {
			found = true
			if rule.DefaultOptions.Outbound != OutboundBypassTag {
				t.Errorf("outbound = %q, want %q", rule.DefaultOptions.Outbound, OutboundBypassTag)
			}
		}
	}
	if !found {
		t.Error("process rule missing from route rules")
	}

	// and contributes nothing at all to DNS.
	if !reflect.DeepEqual(got.DNS.Rules, baseline.DNS.Rules) {
		t.Errorf("DNS rules changed by a process rule:\n got %#v\nwant %#v", got.DNS.Rules, baseline.DNS.Rules)
	}
}

func TestFindProcessFollowsTheRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule Rule
		want bool
	}{
		{"process rule", Rule{ProcessName: []string{"curl.exe"}, Outbound: "bypass"}, true},
		{"domain rule", Rule{Domains: "example.com", Outbound: "proxy"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := routingOptions(t, HiddifyOptions{Rules: []Rule{tc.rule}})
			if got := options.Route.FindProcess; got != tc.want {
				t.Errorf("FindProcess = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDomainPlusProcessIsAGenerationError(t *testing.T) {
	opt := HiddifyOptions{
		DNSOptions: DNSOptions{EnableDNSRouting: true},
		Rules: []Rule{{
			Domains:     "example.com",
			ProcessName: []string{"curl.exe"},
			Outbound:    "proxy",
		}},
	}
	err := setRoutingOptions(&option.Options{DNS: &option.DNSOptions{}}, &opt)
	if err == nil {
		t.Fatal("expected an error for a rule matching both a domain and a process")
	}
	if !strings.Contains(err.Error(), "example.com") {
		t.Errorf("error does not name the offending rule: %v", err)
	}
}

// The DNS guard replaced a rule that IsValid used to drop. Prove the
// generated config is unchanged for the rules that already existed.
func TestDNSGuardDoesNotChangeExistingRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule Rule
	}{
		{"ip only", Rule{IP: "1.1.1.1", Outbound: "bypass"}},
		{"port only", Rule{Port: "443", Outbound: "proxy"}},
		{"protocol only", Rule{Protocol: "quic", Outbound: "block"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, fakeDNS := range []bool{false, true} {
				base := HiddifyOptions{DNSOptions: DNSOptions{EnableDNSRouting: true, EnableFakeDNS: fakeDNS}}
				withRule := base
				withRule.Rules = []Rule{tc.rule}

				if got, want := routingOptions(t, withRule).DNS.Rules, routingOptions(t, base).DNS.Rules; !reflect.DeepEqual(got, want) {
					t.Errorf("fakeDNS=%v: DNS rules changed:\n got %#v\nwant %#v", fakeDNS, got, want)
				}
			}
		})
	}
}
