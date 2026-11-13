package main

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

func resolveTarget(o options, host, domain string) (options, error) {
	o.domain = domain
	if o.realm == "" && o.authMethod == "gssapi" {
		o.realm = strings.ToUpper(domain)
	}
	if strings.ContainsAny(o.realm, "\r\n\x00 /@") {
		return o, errors.New("invalid Kerberos realm")
	}
	if o.relay == "" {
		o.relay = "mailgw." + domain
	}
	var err error
	o.relay, err = dnsName(o.relay)
	if err != nil {
		return o, fmt.Errorf("invalid --relay: %w", err)
	}
	if o.hello == "" {
		o.hello = host
	}
	if o.hello, err = dnsName(o.hello); err != nil {
		return o, fmt.Errorf("invalid --hostname: %w", err)
	}
	if o.spn == "" && o.authMethod == "gssapi" {
		o.spn = "smtp/" + o.relay
	}
	if strings.ContainsAny(o.spn, "\r\n\x00") {
		return o, errors.New("invalid service principal")
	}
	return o, nil
}

func parseDNSServers(servers []string) ([]netip.AddrPort, error) {
	var endpoints []netip.AddrPort
	for _, server := range servers {
		endpoint, err := netip.ParseAddrPort(server)
		if err != nil {
			address, addressErr := netip.ParseAddr(server)
			if addressErr != nil {
				return nil, fmt.Errorf("--dns-server must be a numeric IP or IP:port: %q", server)
			}
			endpoint = netip.AddrPortFrom(address, 53)
		}
		if !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
			return nil, fmt.Errorf("invalid --dns-server %q", server)
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}
