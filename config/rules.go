package config

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
)

type Rule struct {
	RuleSetUrl  string   `json:"rule-set-url"`
	Domains     string   `json:"domains"`
	IP          string   `json:"ip"`
	Port        string   `json:"port"`
	Network     string   `json:"network"`
	Protocol    string   `json:"protocol"`
	ProcessName []string `json:"process-name,omitempty"`
	ProcessPath []string `json:"process-path,omitempty"`
	// Invert negates the whole match, so the rule fires for every connection
	// the other fields do not describe. It is what an include selection needs:
	// "everything that is not one of these processes leaves the tunnel", with
	// the selected processes falling through to the final outbound. Expressing
	// it this way keeps Route.Final on the proxy, so the DNS, LAN and
	// platform rules that run before this one are untouched.
	Invert   bool   `json:"invert,omitempty"`
	Outbound string `json:"outbound"`
}

func (r *Rule) MakeRule() option.DefaultRule {
	rule := option.DefaultRule{}
	if len(r.Domains) > 0 {
		rule = makeDomainRule(rule, strings.Split(r.Domains, ","))
	}
	if len(r.IP) > 0 {
		rule = makeIpRule(rule, strings.Split(r.IP, ","))
	}
	if len(r.Port) > 0 {
		rule = makePortRule(rule, strings.Split(r.Port, ","))
	}
	if len(r.Network) > 0 {
		rule.Network = append(rule.Network, r.Network)
	}
	if len(r.Protocol) > 0 {
		rule.Protocol = append(rule.Protocol, strings.Split(r.Protocol, ",")...)
	}
	if len(r.ProcessName) > 0 {
		rule.ProcessName = append(rule.ProcessName, r.ProcessName...)
	}
	if len(r.ProcessPath) > 0 {
		rule.ProcessPath = append(rule.ProcessPath, expandProcessPaths(r.ProcessPath)...)
	}
	// Set last and unconditionally: option.DefaultRule.IsValid ignores Invert
	// when it decides whether a rule matches anything, so an inverted rule with
	// an empty process list is dropped rather than turned into "invert nothing",
	// which would match every connection and empty the tunnel.
	rule.Invert = r.Invert
	return rule
}

// HasDomainRule reports whether the rule carries a domain match. MakeDNSRule
// reads nothing but Domains, so a rule without one derives no usable DNS rule.
func (r *Rule) HasDomainRule() bool {
	return len(r.Domains) > 0
}

// HasProcessRule reports whether the rule matches on the local process.
func (r *Rule) HasProcessRule() bool {
	return len(r.ProcessName) > 0 || len(r.ProcessPath) > 0
}

func (r *Rule) MakeDNSRule() option.DefaultDNSRule {
	rule := option.DefaultDNSRule{}
	domains := strings.Split(r.Domains, ",")
	for _, item := range domains {
		if strings.HasPrefix(item, "geosite:") {
			rule.Geosite = append(rule.Geosite, strings.TrimPrefix(item, "geosite:"))
		} else if strings.HasPrefix(item, "full:") {
			rule.Domain = append(rule.Domain, strings.ToLower(strings.TrimPrefix(item, "full:")))
		} else if strings.HasPrefix(item, "domain:") {
			rule.DomainSuffix = append(rule.DomainSuffix, strings.ToLower(strings.TrimPrefix(item, "domain:")))
		} else if strings.HasPrefix(item, "regexp:") {
			rule.DomainRegex = append(rule.DomainRegex, strings.ToLower(strings.TrimPrefix(item, "regexp:")))
		} else if strings.HasPrefix(item, "keyword:") {
			rule.DomainKeyword = append(rule.DomainKeyword, strings.ToLower(strings.TrimPrefix(item, "keyword:")))
		}
	}
	return rule
}

func makeDomainRule(options option.DefaultRule, list []string) option.DefaultRule {
	for _, item := range list {
		if strings.HasPrefix(item, "geosite:") {
			options.Geosite = append(options.Geosite, strings.TrimPrefix(item, "geosite:"))
		} else if strings.HasPrefix(item, "full:") {
			options.Domain = append(options.Domain, strings.ToLower(strings.TrimPrefix(item, "full:")))
		} else if strings.HasPrefix(item, "domain:") {
			options.DomainSuffix = append(options.DomainSuffix, strings.ToLower(strings.TrimPrefix(item, "domain:")))
		} else if strings.HasPrefix(item, "regexp:") {
			options.DomainRegex = append(options.DomainRegex, strings.ToLower(strings.TrimPrefix(item, "regexp:")))
		} else if strings.HasPrefix(item, "keyword:") {
			options.DomainKeyword = append(options.DomainKeyword, strings.ToLower(strings.TrimPrefix(item, "keyword:")))
		}
	}
	return options
}

func makeIpRule(options option.DefaultRule, list []string) option.DefaultRule {
	for _, item := range list {
		if strings.HasPrefix(item, "geoip:") {
			options.GeoIP = append(options.GeoIP, strings.TrimPrefix(item, "geoip:"))
		} else {
			options.IPCIDR = append(options.IPCIDR, item)
		}
	}
	return options
}

func makePortRule(options option.DefaultRule, list []string) option.DefaultRule {
	for _, item := range list {
		if strings.Contains(item, ":") {
			options.PortRange = append(options.PortRange, item)
		} else if i, err := strconv.Atoi(item); err == nil {
			options.Port = append(options.Port, uint16(i))
		}
	}
	return options
}
