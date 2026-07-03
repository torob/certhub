package dnspropagation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestCheckerDoHLookupTXT(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		resp, err := dnsResponse(body, dnsmessage.TypeTXT, "txt-value", false)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	}))
	defer server.Close()

	checker, err := NewChecker(Config{Type: TypeDoH, Endpoint: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	visible, err := checker.TXTVisible(context.Background(), "example.com", "txt-value")
	if err != nil {
		t.Fatal(err)
	}
	if !visible {
		t.Fatalf("TXT was not visible")
	}
}

func TestCheckerRegularDNSFallsBackToTCP(t *testing.T) {
	udpAddr, stopUDP := startUDPTruncatedDNSServer(t)
	defer stopUDP()
	tcpAddr, stopTCP := startTCPDNSServer(t, udpAddr.Port, "txt-value")
	defer stopTCP()
	if udpAddr.Port != tcpAddr.Port || udpAddr.IP.String() != tcpAddr.IP.String() {
		t.Fatalf("test server addresses do not match: udp=%s tcp=%s", udpAddr, tcpAddr)
	}
	checker, err := NewChecker(Config{Type: TypeDNS, Endpoint: udpAddr.String()})
	if err != nil {
		t.Fatal(err)
	}
	visible, err := checker.TXTVisible(context.Background(), "example.com", "txt-value")
	if err != nil {
		t.Fatal(err)
	}
	if !visible {
		t.Fatalf("TXT was not visible")
	}
}

func TestCheckerFollowsCNAME(t *testing.T) {
	called := 0
	values, err := followCNAME(context.Background(), "alias.example.com", func(_ context.Context, name string, _ dnsmessage.Type) (dnsAnswer, error) {
		called++
		if name == "alias.example.com" {
			return dnsAnswer{cname: "target.example.com."}, nil
		}
		return dnsAnswer{txt: []string{"txt-value"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if called != 2 || len(values) != 1 || values[0] != "txt-value" {
		t.Fatalf("called=%d values=%v", called, values)
	}
}

func TestCheckerDoTThroughHTTPConnectProxy(t *testing.T) {
	tlsAddr, roots, stopDNS := startTLSDNSServer(t, "txt-value")
	defer stopDNS()
	proxyURL, stopProxy := startConnectProxy(t)
	defer stopProxy()

	checker, err := NewChecker(Config{
		Type:          TypeDoT,
		Endpoint:      tlsAddr,
		TLSServerName: "localhost",
		ProxyName:     "corp_proxy",
		ProxyURL:      proxyURL,
		TLSConfig:     &tls.Config{RootCAs: roots},
	})
	if err != nil {
		t.Fatal(err)
	}
	visible, err := checker.TXTVisible(context.Background(), "example.com", "txt-value")
	if err != nil {
		t.Fatal(err)
	}
	if !visible {
		t.Fatalf("TXT was not visible")
	}
}

func TestCheckerThroughRealSquidProxies(t *testing.T) {
	if os.Getenv("CERTHUB_REAL_PROXY_TEST") != "1" {
		t.Skip("set CERTHUB_REAL_PROXY_TEST=1 to run real Squid proxy resolver tests")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatalf("docker is required for real Squid proxy tests: %v", err)
	}
	image := buildSquidTestImage(t, docker)
	proxy := startSquidProxy(t, docker, image)

	dohURL, dohCertPEM, stopDoH := startTLSDOHServer(t, "txt-value")
	defer stopDoH()
	dotAddr, dotRoots, stopDoT := startTLSDNSServer(t, "txt-value")
	defer stopDoT()

	tests := []struct {
		name     string
		resolver string
		proxyURL *url.URL
	}{
		{name: "doh_http_proxy", resolver: TypeDoH, proxyURL: proxy.httpURL},
		{name: "doh_https_proxy", resolver: TypeDoH, proxyURL: proxy.httpsURL},
		{name: "dot_http_proxy", resolver: TypeDoT, proxyURL: proxy.httpURL},
		{name: "dot_https_proxy", resolver: TypeDoT, proxyURL: proxy.httpsURL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := proxy.accessLogLines(t)
			switch tc.resolver {
			case TypeDoH:
				roots := certPoolFromPEMs(t, dohCertPEM, proxy.certPEM)
				transport := http.DefaultTransport.(*http.Transport).Clone()
				transport.Proxy = http.ProxyURL(tc.proxyURL)
				transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
				checker, err := NewChecker(Config{
					Type:       TypeDoH,
					Endpoint:   dohURL,
					ProxyName:  "squid_proxy",
					HTTPClient: &http.Client{Transport: transport, Timeout: 30 * time.Second},
				})
				if err != nil {
					t.Fatal(err)
				}
				visible, err := checker.TXTVisible(context.Background(), "example.com", "txt-value")
				transport.CloseIdleConnections()
				if err != nil {
					t.Fatal(err)
				}
				if !visible {
					t.Fatalf("TXT was not visible")
				}
			case TypeDoT:
				checker, err := NewChecker(Config{
					Type:           TypeDoT,
					Endpoint:       dotAddr,
					TLSServerName:  "localhost",
					ProxyName:      "squid_proxy",
					ProxyURL:       tc.proxyURL,
					TLSConfig:      &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: dotRoots},
					ProxyTLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: proxy.roots},
				})
				if err != nil {
					t.Fatal(err)
				}
				visible, err := checker.TXTVisible(context.Background(), "example.com", "txt-value")
				if err != nil {
					t.Fatal(err)
				}
				if !visible {
					t.Fatalf("TXT was not visible")
				}
			default:
				t.Fatalf("unsupported resolver %s", tc.resolver)
			}
			proxy.waitForAccessLogAdvance(t, before)
		})
	}
	log := proxy.accessLog(t)
	for _, target := range []string{dohURLHost(t, dohURL), dotAddr} {
		if !strings.Contains(log, target) {
			t.Fatalf("squid access log does not contain CONNECT target %s:\n%s", target, log)
		}
	}
}

func startUDPTruncatedDNSServer(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp, err := dnsResponse(buf[:n], dnsmessage.TypeTXT, "", true)
			if err == nil {
				_, _ = conn.WriteToUDP(resp, addr)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr), func() {
		_ = conn.Close()
		<-done
	}
}

func startTCPDNSServer(t *testing.T, port int, txt string) (*net.TCPAddr, func()) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go serveDNSOverStream(ln, done, txt)
	return ln.Addr().(*net.TCPAddr), func() {
		_ = ln.Close()
		<-done
	}
}

func startTLSDNSServer(t *testing.T, txt string) (string, *x509.CertPool, func()) {
	t.Helper()
	cert, roots := testTLSCertificate(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tlsListener(ln, cert)
	done := make(chan struct{})
	go serveDNSOverStream(tlsLn, done, txt)
	return ln.Addr().String(), roots, func() {
		_ = tlsLn.Close()
		<-done
	}
}

func startTLSDOHServer(t *testing.T, txt string) (string, []byte, func()) {
	t.Helper()
	cert, _, certPEM, _ := testTLSCertificatePEM(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		resp, err := dnsResponse(body, dnsmessage.TypeTXT, txt, false)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resp)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	return server.URL, certPEM, server.Close
}

func serveDNSOverStream(ln net.Listener, done chan<- struct{}, txt string) {
	defer close(done)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			var size [2]byte
			if _, err := io.ReadFull(conn, size[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(conn, query); err != nil {
				return
			}
			resp, err := dnsResponse(query, dnsmessage.TypeTXT, txt, false)
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(size[:], uint16(len(resp)))
			_, _ = conn.Write(append(size[:], resp...))
		}()
	}
}

func startConnectProxy(t *testing.T) (*url.URL, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect required", http.StatusMethodNotAllowed)
			return
		}
		target, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unavailable", http.StatusInternalServerError)
			_ = target.Close()
			return
		}
		client, _, err := hijacker.Hijack()
		if err != nil {
			_ = target.Close()
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go func() {
			defer client.Close()
			defer target.Close()
			_, _ = io.Copy(target, client)
		}()
		go func() {
			defer client.Close()
			defer target.Close()
			_, _ = io.Copy(client, target)
		}()
	}))
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u, server.Close
}

type squidProxy struct {
	docker   string
	name     string
	httpURL  *url.URL
	httpsURL *url.URL
	roots    *x509.CertPool
	certPEM  []byte
}

func buildSquidTestImage(t *testing.T, docker string) string {
	t.Helper()
	image := "certhub-squid-real-proxy-test:ubuntu-24.04"
	dir := t.TempDir()
	dockerfile := []byte(`FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends squid-openssl ca-certificates && rm -rf /var/lib/apt/lists/*
`)
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), dockerfile, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(docker, "build", "-t", image, dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build Squid test image: %v\n%s", err, out)
	}
	return image
}

func startSquidProxy(t *testing.T, docker, image string) *squidProxy {
	t.Helper()
	httpPort := freeTCPPort(t)
	httpsPort := freeTCPPort(t)
	_, roots, certPEM, keyPEM := testTLSCertificatePEM(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "proxy.crt"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proxy.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf(`visible_hostname certhub-squid-test
acl allsrc src all
acl CONNECT method CONNECT
acl SSL_ports port 1-65535
acl Safe_ports port 1-65535
http_access allow allsrc
http_port 127.0.0.1:%d
https_port 127.0.0.1:%d tls-cert=/test/proxy.crt tls-key=/test/proxy.key
access_log /tmp/access.log
cache_log /tmp/cache.log
pid_filename /tmp/squid.pid
cache deny all
`, httpPort, httpsPort)
	if err := os.WriteFile(filepath.Join(dir, "squid.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	name := "certhub-squid-real-proxy-test-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	cmd := exec.Command(docker, "run", "-d", "--name", name, "--network", "host", "-v", dir+":/test:ro", image, "squid", "-N", "-f", "/test/squid.conf", "-d", "1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("start Squid container: %v\n%s", err, out)
	}
	proxy := &squidProxy{
		docker:   docker,
		name:     name,
		httpURL:  mustParseURL(t, fmt.Sprintf("http://127.0.0.1:%d", httpPort)),
		httpsURL: mustParseURL(t, fmt.Sprintf("https://localhost:%d", httpsPort)),
		roots:    roots,
		certPEM:  certPEM,
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("squid container logs:\n%s", proxy.containerLogs())
			t.Logf("squid cache log:\n%s", proxy.fileLog("/tmp/cache.log"))
			t.Logf("squid access log:\n%s", proxy.fileLog("/tmp/access.log"))
		}
		_ = exec.Command(docker, "rm", "-f", name).Run()
	})
	waitForTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)))
	waitForTCP(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(httpsPort)))
	return proxy
}

func (p *squidProxy) waitForAccessLogAdvance(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p.accessLogLines(t) > before {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("squid access log did not advance; before=%d log:\n%s", before, p.accessLog(t))
}

func (p *squidProxy) accessLogLines(t *testing.T) int {
	t.Helper()
	log := p.accessLog(t)
	count := 0
	for _, line := range strings.Split(log, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func (p *squidProxy) accessLog(t *testing.T) string {
	t.Helper()
	return p.fileLog("/tmp/access.log")
}

func (p *squidProxy) fileLog(path string) string {
	out, err := exec.Command(p.docker, "exec", p.name, "sh", "-lc", "cat "+path+" 2>/dev/null || true").CombinedOutput()
	if err != nil {
		return string(out)
	}
	return string(out)
}

func (p *squidProxy) containerLogs() string {
	out, err := exec.Command(p.docker, "logs", p.name).CombinedOutput()
	if err != nil {
		return string(out)
	}
	return string(out)
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func dohURLHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for TCP listener %s", addr)
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func dnsResponse(query []byte, answerType dnsmessage.Type, value string, truncated bool) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true, Truncated: truncated})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	if truncated {
		return builder.Finish()
	}
	switch answerType {
	case dnsmessage.TypeTXT:
		err = builder.TXTResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.TXTResource{TXT: []string{value}})
	default:
		err = builder.CNAMEResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(value)})
	}
	if err != nil {
		return nil, err
	}
	return builder.Finish()
}

func testTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	cert, roots, _, _ := testTLSCertificatePEM(t)
	return cert, roots
}

func testTLSCertificatePEM(t *testing.T) (tls.Certificate, *x509.CertPool, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	return cert, roots, certPEM, keyPEM
}

func tlsListener(ln net.Listener, cert tls.Certificate) net.Listener {
	return tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
}

func certPoolFromPEMs(t *testing.T, certs ...[]byte) *x509.CertPool {
	t.Helper()
	roots := x509.NewCertPool()
	for _, cert := range certs {
		if !roots.AppendCertsFromPEM(bytes.TrimSpace(cert)) {
			t.Fatalf("append test certificate to pool failed")
		}
	}
	return roots
}
