package main

import (
	"context"
	"net"
	"strings"
	"testing"
)

// TestNewWebhookTransport covers issue #314: webhook delivery skips TLS
// verification and SSRF checks by default (backward compatible), and both can be
// hardened via -webhookverifytls / -webhookblockprivateips.
func TestNewWebhookTransport(t *testing.T) {
	origTLS, origSSRF := *webhookVerifyTLS, *webhookBlockPrivateIPs
	t.Cleanup(func() {
		*webhookVerifyTLS = origTLS
		*webhookBlockPrivateIPs = origSSRF
	})

	// Defaults preserve current behavior: skip TLS verify, no SSRF dialer.
	*webhookVerifyTLS = false
	*webhookBlockPrivateIPs = false
	tr := newWebhookTransport()
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("default: expected InsecureSkipVerify=true (backward compatible)")
	}
	if tr.DialContext != nil {
		t.Error("default: expected no SSRF dialer installed")
	}

	// Hardened: verify TLS and block private/loopback IPs.
	*webhookVerifyTLS = true
	*webhookBlockPrivateIPs = true
	tr = newWebhookTransport()
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("webhookverifytls=true: expected InsecureSkipVerify=false")
	}
	if tr.DialContext == nil {
		t.Error("webhookblockprivateips=true: expected SSRF dialer installed")
	}
}

// TestSafeDialContextBlocksPrivateIPs proves the SSRF dialer actually refuses to
// connect to loopback and RFC1918/CGNAT/link-local addresses — the real point of
// -webhookblockprivateips, not just that the dialer is installed. Literal IPs
// skip DNS, and the block is the isPrivateOrLoopback check, so no network is hit.
func TestSafeDialContextBlocksPrivateIPs(t *testing.T) {
	// main() populates privateIPBlocks; tests don't run main, so seed it here.
	if len(privateIPBlocks) == 0 {
		for _, cidr := range []string{
			"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"100.64.0.0/10", "169.254.0.0/16", "::1/128", "fe80::/10",
		} {
			if _, block, err := net.ParseCIDR(cidr); err == nil {
				privateIPBlocks = append(privateIPBlocks, block)
			}
		}
	}

	blocked := []string{
		"127.0.0.1:80",       // loopback
		"10.0.0.1:80",        // RFC1918
		"172.16.5.4:443",     // RFC1918
		"192.168.1.1:8080",   // RFC1918
		"169.254.169.254:80", // link-local — the cloud metadata endpoint (classic SSRF target)
		"[::1]:80",           // IPv6 loopback
	}
	for _, addr := range blocked {
		conn, err := safeDialContext(context.Background(), "tcp", addr)
		if conn != nil {
			conn.Close()
		}
		if err == nil {
			t.Errorf("safeDialContext(%q) connected; expected it to be refused", addr)
			continue
		}
		if !strings.Contains(err.Error(), "ssrf") {
			t.Errorf("safeDialContext(%q) err = %q; want an SSRF refusal", addr, err.Error())
		}
	}
}
