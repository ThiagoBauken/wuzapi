package main

import "testing"

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
