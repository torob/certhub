package config

import (
	"net/http"
	"net/url"
	"testing"
)

func TestOutboundHTTPTransportIgnoresAmbientProxyWhenDirect(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://ambient.example:8080")
	transport, err := NewOutboundHTTPTransport(OutboundHTTPConfig{Proxies: map[string]ProxyConfig{}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if transport.Proxy != nil {
		req := &http.Request{URL: mustURL(t, "https://api.example.com")}
		proxy, err := transport.Proxy(req)
		if err != nil {
			t.Fatal(err)
		}
		if proxy != nil {
			t.Fatalf("direct transport used ambient proxy: %s", proxy.Redacted())
		}
	}
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("transport disabled upstream TLS verification")
	}
}

func TestOutboundHTTPTransportUsesOnlyNamedProxy(t *testing.T) {
	transport, err := NewOutboundHTTPTransport(OutboundHTTPConfig{Proxies: map[string]ProxyConfig{
		"corp_proxy": {URL: SecretString("https://proxy.example:8443")},
	}}, "corp_proxy")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{URL: mustURL(t, "https://api.cloudflare.com/client/v4/zones")}
	proxy, err := transport.Proxy(req)
	if err != nil {
		t.Fatal(err)
	}
	if proxy == nil || proxy.String() != "https://proxy.example:8443" {
		t.Fatalf("proxy = %v", proxy)
	}
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("transport disabled upstream TLS verification")
	}
}

func TestOutboundProxyURLReturnsNamedProxy(t *testing.T) {
	proxy, err := OutboundProxyURL(OutboundHTTPConfig{Proxies: map[string]ProxyConfig{
		"corp_proxy": {URL: SecretString("http://proxy.example:8080")},
	}}, "corp_proxy")
	if err != nil {
		t.Fatal(err)
	}
	if proxy.String() != "http://proxy.example:8080" {
		t.Fatalf("proxy = %s", proxy)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
