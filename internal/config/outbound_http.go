package config

import (
	"errors"
	"net/http"
	"net/url"
	"time"
)

func NewOutboundHTTPClient(cfg OutboundHTTPConfig, proxyName string) (*http.Client, error) {
	transport, err := NewOutboundHTTPTransport(cfg, proxyName)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

func NewOutboundHTTPTransport(cfg OutboundHTTPConfig, proxyName string) (*http.Transport, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if proxyName == "" {
		return transport, nil
	}
	proxy, ok := cfg.Proxies[proxyName]
	if !ok {
		return nil, errors.New("outbound proxy is not configured")
	}
	proxyURL, err := url.Parse(string(proxy.URL))
	if err != nil {
		return nil, errors.New("outbound proxy is invalid")
	}
	transport.Proxy = http.ProxyURL(proxyURL)
	return transport, nil
}
