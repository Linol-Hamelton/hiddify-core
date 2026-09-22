package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// An include selection is expressed as one inverted rule, so the key has to
// survive the same kebab-case round trip the process fields already take.
func TestRuleInvertRoundTripsUnderItsKebabKey(t *testing.T) {
	const input = `{"process-path":["C:\\bin\\curl.exe"],"invert":true,"outbound":"bypass"}`

	var rule Rule
	if err := json.Unmarshal([]byte(input), &rule); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !rule.Invert {
		t.Fatal("Invert = false, want true")
	}

	encoded, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"invert":true`) {
		t.Errorf(`"invert":true missing from %s`, encoded)
	}
}

// Every rule written before include mode existed has to round-trip unchanged.
func TestRuleWithoutInvertOmitsTheKey(t *testing.T) {
	encoded, err := json.Marshal(Rule{ProcessPath: []string{`C:\bin\curl.exe`}, Outbound: "bypass"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "invert") {
		t.Errorf("invert key leaked into %s", encoded)
	}
}

func TestMakeRuleCarriesInvert(t *testing.T) {
	rule := (&Rule{ProcessPath: []string{`C:\bin\curl.exe`}, Invert: true}).MakeRule()
	if !rule.Invert {
		t.Fatal("Invert = false, want true")
	}
	if !rule.IsValid() {
		t.Error("inverted process rule rejected by IsValid")
	}
}

// The guarantee that makes include mode safe to ship: an include selection
// with nothing in it must protect everything rather than nothing. The rule
// carries no process path, IsValid drops it, and Route.Final keeps every
// connection on the proxy.
func TestEmptyIncludeSelectionProtectsEverything(t *testing.T) {
	opt := HiddifyOptions{Rules: []Rule{{Invert: true, Outbound: "bypass"}}}
	options := routingOptions(t, opt)

	for _, rule := range options.Route.Rules {
		if rule.DefaultOptions.Invert {
			t.Fatalf("an empty inverted rule reached the router: %#v", rule.DefaultOptions)
		}
	}
	if options.Route.Final != OutboundMainProxyTag {
		t.Errorf("Final = %q, want %q", options.Route.Final, OutboundMainProxyTag)
	}
}

// Include mode must not move the final outbound. Everything that runs before
// the per-app rules - the DNS hijack on port 53, the LAN bypass, the Android
// self-bypass - depends on unmatched traffic still ending on the proxy.
func TestIncludeSelectionKeepsFinalOnTheProxy(t *testing.T) {
	opt := HiddifyOptions{Rules: []Rule{{
		ProcessPath: []string{`C:\bin\curl.exe`},
		Invert:      true,
		Outbound:    "bypass",
	}}}
	options := routingOptions(t, opt)

	if options.Route.Final != OutboundMainProxyTag {
		t.Errorf("Final = %q, want %q", options.Route.Final, OutboundMainProxyTag)
	}
	if !options.Route.FindProcess {
		t.Error("FindProcess = false; the router cannot match a process path without it")
	}

	var found bool
	for _, rule := range options.Route.Rules {
		if !reflect.DeepEqual([]string(rule.DefaultOptions.ProcessPath), []string{`C:\bin\curl.exe`}) {
			continue
		}
		found = true
		if !rule.DefaultOptions.Invert {
			t.Error("the rule reached the router without Invert; it would route the selection out instead of in")
		}
		if rule.DefaultOptions.Outbound != OutboundBypassTag {
			t.Errorf("outbound = %q, want %q", rule.DefaultOptions.Outbound, OutboundBypassTag)
		}
	}
	if !found {
		t.Error("inverted process rule missing from route rules")
	}
}

// Include mode carries the same rule through to DNS, inverted the same way:
// everything that is not in the selection leaves the tunnel, so everything
// that is not in the selection must resolve outside it too. Without this the
// unselected processes would take their addresses from the tunnel's resolver
// while their sockets went direct.
func TestInvertedProcessRuleResolvesTheRestLocally(t *testing.T) {
	base := HiddifyOptions{DNSOptions: DNSOptions{EnableDNSRouting: true}}
	withInvert := base
	withInvert.Rules = []Rule{{ProcessPath: []string{`C:\bin\curl.exe`}, Invert: true, Outbound: "bypass"}}

	baseline := routingOptions(t, base)
	got := routingOptions(t, withInvert)

	var found int
	for _, rule := range got.DNS.Rules {
		if !reflect.DeepEqual([]string(rule.DefaultOptions.ProcessPath), []string{`C:\bin\curl.exe`}) {
			continue
		}
		found++
		if !rule.DefaultOptions.Invert {
			t.Error("the DNS rule is not inverted; it would send the selection to the local resolver and leave everything else on the tunnel's - exactly backwards")
		}
		if rule.DefaultOptions.Server != DNSLocalTag {
			t.Errorf("server = %q, want %q", rule.DefaultOptions.Server, DNSLocalTag)
		}
	}
	if found != 1 {
		t.Errorf("found %d inverted process DNS rules, want exactly 1", found)
	}
	if len(got.DNS.Rules) != len(baseline.DNS.Rules)+1 {
		t.Errorf("inverted rule added %d DNS rules, want 1", len(got.DNS.Rules)-len(baseline.DNS.Rules))
	}
}

// The DNS rule has to match the same processes as the route rule, or a
// process could take its addresses from one side of the tunnel and its
// sockets from the other.
func TestProcessDNSRuleMirrorsTheRouteRule(t *testing.T) {
	opt := HiddifyOptions{
		DNSOptions: DNSOptions{EnableDNSRouting: true},
		Rules: []Rule{{
			ProcessName: []string{"curl.exe"},
			ProcessPath: []string{`C:\bin\curl.exe`},
			Invert:      true,
			Outbound:    "bypass",
		}},
	}
	options := routingOptions(t, opt)

	var route *option.DefaultRule
	for i, rule := range options.Route.Rules {
		if len(rule.DefaultOptions.ProcessPath) > 0 {
			route = &options.Route.Rules[i].DefaultOptions
		}
	}
	if route == nil {
		t.Fatal("no process route rule generated")
	}

	var matched bool
	for _, rule := range options.DNS.Rules {
		if rule.DefaultOptions.Server != DNSLocalTag {
			continue
		}
		matched = true
		if !reflect.DeepEqual(rule.DefaultOptions.ProcessPath, route.ProcessPath) {
			t.Errorf("ProcessPath differs:\n dns %#v\nroute %#v", rule.DefaultOptions.ProcessPath, route.ProcessPath)
		}
		if !reflect.DeepEqual(rule.DefaultOptions.ProcessName, route.ProcessName) {
			t.Errorf("ProcessName differs:\n dns %#v\nroute %#v", rule.DefaultOptions.ProcessName, route.ProcessName)
		}
		if rule.DefaultOptions.Invert != route.Invert {
			t.Errorf("Invert differs: dns %v, route %v", rule.DefaultOptions.Invert, route.Invert)
		}
	}
	if !matched {
		t.Error("no local-resolver DNS rule generated for the bypassed processes")
	}
}

// Exclude mode is the shipped behaviour and must not move: no Invert, one
// rule per path, bypass outbound, proxy final.
func TestExcludeSelectionIsUnchanged(t *testing.T) {
	opt := HiddifyOptions{Rules: []Rule{
		{ProcessPath: []string{`C:\bin\a.exe`}, Outbound: "bypass"},
		{ProcessPath: []string{`C:\bin\b.exe`}, Outbound: "bypass"},
	}}
	options := routingOptions(t, opt)

	var matched int
	for _, rule := range options.Route.Rules {
		if len(rule.DefaultOptions.ProcessPath) == 0 {
			continue
		}
		matched++
		if rule.DefaultOptions.Invert {
			t.Errorf("exclude rule %#v gained Invert", rule.DefaultOptions)
		}
		if rule.DefaultOptions.Outbound != OutboundBypassTag {
			t.Errorf("outbound = %q, want %q", rule.DefaultOptions.Outbound, OutboundBypassTag)
		}
	}
	if matched != 2 {
		t.Errorf("matched %d process rules, want 2", matched)
	}
	if options.Route.Final != OutboundMainProxyTag {
		t.Errorf("Final = %q, want %q", options.Route.Final, OutboundMainProxyTag)
	}
}

// option.DefaultRule is an upstream type: if a future bump ever makes IsValid
// count Invert as content, the empty-selection guarantee silently flips from
// "protect everything" to "protect nothing". Fail here instead.
func TestIsValidStillIgnoresInvert(t *testing.T) {
	if (option.DefaultRule{Invert: true, Outbound: OutboundBypassTag}).IsValid() {
		t.Fatal("option.DefaultRule.IsValid now counts Invert as content; the empty-include-selection guard is broken")
	}
}
