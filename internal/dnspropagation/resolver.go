package dnspropagation

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	TypeSystem = "system"
	TypeDNS    = "dns"
	TypeDoH    = "doh"
	TypeDoT    = "dot"

	maxCNAMEHops  = 8
	lookupTimeout = 5 * time.Second
)

type Config struct {
	Type           string
	Endpoint       string
	TLSServerName  string
	ProxyName      string
	ProxyURL       *url.URL
	HTTPClient     *http.Client
	TLSConfig      *tls.Config
	ProxyTLSConfig *tls.Config
}

type Checker struct {
	resolver resolver
	metadata map[string]any
}

type resolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

func NewChecker(cfg Config) (*Checker, error) {
	resolverType := cfg.Type
	if resolverType == "" {
		resolverType = TypeSystem
	}
	metadata := map[string]any{"dns_propagation_resolver_type": resolverType}
	var r resolver
	switch resolverType {
	case TypeSystem:
		if cfg.Endpoint != "" || cfg.TLSServerName != "" || cfg.ProxyName != "" || cfg.ProxyURL != nil {
			return nil, errors.New("system resolver does not accept endpoint, tls server name, or proxy")
		}
		r = systemResolver{}
	case TypeDNS:
		if cfg.Endpoint == "" {
			return nil, errors.New("dns resolver endpoint is required")
		}
		if cfg.TLSServerName != "" || cfg.ProxyName != "" || cfg.ProxyURL != nil {
			return nil, errors.New("dns resolver does not accept tls server name or proxy")
		}
		r = wireResolver{network: TypeDNS, endpoint: cfg.Endpoint}
		metadata["dns_propagation_resolver_endpoint"] = cfg.Endpoint
	case TypeDoH:
		if cfg.Endpoint == "" {
			return nil, errors.New("doh resolver endpoint is required")
		}
		client := cfg.HTTPClient
		if client == nil {
			client = directHTTPClient()
		}
		r = dohResolver{endpoint: cfg.Endpoint, client: client}
		metadata["dns_propagation_resolver_endpoint"] = cfg.Endpoint
		if cfg.ProxyName != "" {
			metadata["dns_propagation_resolver_proxy"] = cfg.ProxyName
		}
	case TypeDoT:
		if cfg.Endpoint == "" {
			return nil, errors.New("dot resolver endpoint is required")
		}
		serverName := cfg.TLSServerName
		if serverName == "" {
			host, _, err := net.SplitHostPort(cfg.Endpoint)
			if err != nil {
				return nil, err
			}
			serverName = strings.Trim(host, "[]")
		}
		r = wireResolver{network: TypeDoT, endpoint: cfg.Endpoint, tlsServerName: serverName, proxyURL: cfg.ProxyURL, tlsConfig: cfg.TLSConfig, proxyTLSConfig: cfg.ProxyTLSConfig}
		metadata["dns_propagation_resolver_endpoint"] = cfg.Endpoint
		metadata["dns_propagation_resolver_tls_server_name"] = serverName
		if cfg.ProxyName != "" {
			metadata["dns_propagation_resolver_proxy"] = cfg.ProxyName
		}
	default:
		return nil, fmt.Errorf("unsupported dns propagation resolver type %s", resolverType)
	}
	return &Checker{resolver: r, metadata: metadata}, nil
}

func (c *Checker) TXTVisible(ctx context.Context, recordName, txtValue string) (bool, error) {
	values, err := c.resolver.LookupTXT(ctx, recordName)
	if err != nil {
		return false, err
	}
	for _, value := range values {
		if value == txtValue {
			return true, nil
		}
	}
	return false, nil
}

func (c *Checker) Metadata() map[string]any {
	out := make(map[string]any, len(c.metadata))
	for key, value := range c.metadata {
		out[key] = value
	}
	return out
}

type systemResolver struct{}

func (systemResolver) LookupTXT(ctx context.Context, recordName string) ([]string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	return net.DefaultResolver.LookupTXT(lookupCtx, recordName)
}

type wireResolver struct {
	network        string
	endpoint       string
	tlsServerName  string
	proxyURL       *url.URL
	tlsConfig      *tls.Config
	proxyTLSConfig *tls.Config
}

func (r wireResolver) LookupTXT(ctx context.Context, recordName string) ([]string, error) {
	return followCNAME(ctx, recordName, r.query)
}

func (r wireResolver) query(ctx context.Context, recordName string, qtype dnsmessage.Type) (dnsAnswer, error) {
	msg, id, err := buildQuery(recordName, qtype)
	if err != nil {
		return dnsAnswer{}, err
	}
	switch r.network {
	case TypeDNS:
		answer, truncated, err := r.queryUDP(ctx, msg, id)
		if err == nil && !truncated {
			return answer, nil
		}
		tcpAnswer, tcpErr := r.queryTCP(ctx, msg, id)
		if tcpErr != nil {
			if err != nil {
				return dnsAnswer{}, fmt.Errorf("udp lookup failed: %w; tcp fallback failed: %w", err, tcpErr)
			}
			return dnsAnswer{}, tcpErr
		}
		return tcpAnswer, nil
	case TypeDoT:
		return r.queryTLS(ctx, msg, id)
	default:
		return dnsAnswer{}, fmt.Errorf("unsupported wire resolver network %s", r.network)
	}
}

func (r wireResolver) queryUDP(ctx context.Context, msg []byte, id uint16) (dnsAnswer, bool, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(lookupCtx, "udp", r.endpoint)
	if err != nil {
		return dnsAnswer{}, false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(lookupTimeout))
	if _, err := conn.Write(msg); err != nil {
		return dnsAnswer{}, false, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return dnsAnswer{}, false, err
	}
	answer, err := parseAnswer(buf[:n], id)
	if err != nil {
		return dnsAnswer{}, false, err
	}
	return answer, answer.truncated, nil
}

func (r wireResolver) queryTCP(ctx context.Context, msg []byte, id uint16) (dnsAnswer, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(lookupCtx, "tcp", r.endpoint)
	if err != nil {
		return dnsAnswer{}, err
	}
	defer conn.Close()
	return exchangeTCP(conn, msg, id)
}

func (r wireResolver) queryTLS(ctx context.Context, msg []byte, id uint16) (dnsAnswer, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: r.tlsServerName}
	if r.tlsConfig != nil {
		config = r.tlsConfig.Clone()
		config.ServerName = r.tlsServerName
		if config.MinVersion == 0 {
			config.MinVersion = tls.VersionTLS12
		}
	}
	var conn net.Conn
	var err error
	if r.proxyURL != nil {
		conn, err = dialHTTPProxy(lookupCtx, r.proxyURL, r.endpoint, r.proxyTLSConfig)
		if err != nil {
			return dnsAnswer{}, err
		}
		tlsConn := tls.Client(conn, config)
		if err := tlsConn.HandshakeContext(lookupCtx); err != nil {
			_ = conn.Close()
			return dnsAnswer{}, err
		}
		conn = tlsConn
	} else {
		var dialer tls.Dialer
		dialer.Config = config
		conn, err = dialer.DialContext(lookupCtx, "tcp", r.endpoint)
		if err != nil {
			return dnsAnswer{}, err
		}
	}
	defer conn.Close()
	return exchangeTCP(conn, msg, id)
}

type dohResolver struct {
	endpoint string
	client   *http.Client
}

func (r dohResolver) LookupTXT(ctx context.Context, recordName string) ([]string, error) {
	return followCNAME(ctx, recordName, r.query)
}

func (r dohResolver) query(ctx context.Context, recordName string, qtype dnsmessage.Type) (dnsAnswer, error) {
	msg, id, err := buildQuery(recordName, qtype)
	if err != nil {
		return dnsAnswer{}, err
	}
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(lookupCtx, http.MethodPost, r.endpoint, bytes.NewReader(msg))
	if err != nil {
		return dnsAnswer{}, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		return dnsAnswer{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return dnsAnswer{}, fmt.Errorf("doh server returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return dnsAnswer{}, err
	}
	return parseAnswer(body, id)
}

func followCNAME(ctx context.Context, recordName string, query func(context.Context, string, dnsmessage.Type) (dnsAnswer, error)) ([]string, error) {
	name := recordName
	for i := 0; i <= maxCNAMEHops; i++ {
		answer, err := query(ctx, name, dnsmessage.TypeTXT)
		if err != nil {
			return nil, err
		}
		if len(answer.txt) > 0 {
			return answer.txt, nil
		}
		if answer.cname == "" {
			return nil, nil
		}
		name = answer.cname
	}
	return nil, errors.New("dns cname chain is too deep")
}

type dnsAnswer struct {
	txt       []string
	cname     string
	truncated bool
}

func buildQuery(recordName string, qtype dnsmessage.Type) ([]byte, uint16, error) {
	name, err := dnsmessage.NewName(absoluteDNSName(recordName))
	if err != nil {
		return nil, 0, err
	}
	id, err := queryID()
	if err != nil {
		return nil, 0, err
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	msg, err := builder.Finish()
	if err != nil {
		return nil, 0, err
	}
	return msg, id, nil
}

func parseAnswer(msg []byte, id uint16) (dnsAnswer, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(msg)
	if err != nil {
		return dnsAnswer{}, err
	}
	if header.ID != id {
		return dnsAnswer{}, errors.New("dns response id mismatch")
	}
	if !header.Response {
		return dnsAnswer{}, errors.New("dns response flag is missing")
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return dnsAnswer{}, fmt.Errorf("dns response code %s", header.RCode.String())
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return dnsAnswer{}, err
	}
	answer := dnsAnswer{truncated: header.Truncated}
	for {
		h, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return answer, nil
		}
		if err != nil {
			return dnsAnswer{}, err
		}
		switch h.Type {
		case dnsmessage.TypeTXT:
			txt, err := parser.TXTResource()
			if err != nil {
				return dnsAnswer{}, err
			}
			answer.txt = append(answer.txt, strings.Join(txt.TXT, ""))
		case dnsmessage.TypeCNAME:
			cname, err := parser.CNAMEResource()
			if err != nil {
				return dnsAnswer{}, err
			}
			if answer.cname == "" {
				answer.cname = cname.CNAME.String()
			}
		default:
			if err := parser.SkipAnswer(); err != nil {
				return dnsAnswer{}, err
			}
		}
	}
}

func exchangeTCP(conn net.Conn, msg []byte, id uint16) (dnsAnswer, error) {
	_ = conn.SetDeadline(time.Now().Add(lookupTimeout))
	if len(msg) > 65535 {
		return dnsAnswer{}, errors.New("dns query is too large")
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(msg)))
	if _, err := conn.Write(append(size[:], msg...)); err != nil {
		return dnsAnswer{}, err
	}
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return dnsAnswer{}, err
	}
	n := binary.BigEndian.Uint16(size[:])
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return dnsAnswer{}, err
	}
	return parseAnswer(resp, id)
}

func dialHTTPProxy(ctx context.Context, proxyURL *url.URL, target string, proxyTLSConfig *tls.Config) (net.Conn, error) {
	var dialer net.Dialer
	proxyAddr := proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		switch proxyURL.Scheme {
		case "http":
			proxyAddr = net.JoinHostPort(proxyAddr, "80")
		case "https":
			proxyAddr = net.JoinHostPort(proxyAddr, "443")
		}
	}
	var conn net.Conn
	var err error
	switch proxyURL.Scheme {
	case "http":
		conn, err = dialer.DialContext(ctx, "tcp", proxyAddr)
	case "https":
		config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: strings.Trim(proxyURL.Hostname(), "[]")}
		if proxyTLSConfig != nil {
			config = proxyTLSConfig.Clone()
			config.ServerName = strings.Trim(proxyURL.Hostname(), "[]")
			if config.MinVersion == 0 {
				config.MinVersion = tls.VersionTLS12
			}
		}
		tlsDialer := tls.Dialer{NetDialer: &dialer, Config: config}
		conn, err = tlsDialer.DialContext(ctx, "tcp", proxyAddr)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %s", proxyURL.Scheme)
	}
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: target},
		Host:   target,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		credentials := proxyURL.User.Username() + ":" + password
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy CONNECT returned HTTP %d", resp.StatusCode)
	}
	if reader.Buffered() == 0 {
		return conn, nil
	}
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.reader.Buffered() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

func directHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

func absoluteDNSName(value string) string {
	if strings.HasSuffix(value, ".") {
		return value
	}
	return value + "."
}

func queryID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, errors.New("dns query entropy unavailable")
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
