package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	DefaultListLimit = 100
	MaxListLimit     = 1000
)

var (
	machineNameRE       = regexp.MustCompile(`^[a-z](?:[a-z0-9_]{0,62}[a-z0-9])?$`)
	correlationIDRE     = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	tokenHashRE         = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	uuidRE              = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	dnsLabelRE          = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	certificateScopeRE  = regexp.MustCompile(`^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	encryptedEnvelopeRE = regexp.MustCompile(`^\{`)
)

type ListOptions struct {
	Limit  int
	Offset int
}

func NormalizeListOptions(opts ListOptions) (ListOptions, error) {
	if opts.Limit == 0 {
		opts.Limit = DefaultListLimit
	}
	if opts.Limit < 0 || opts.Limit > MaxListLimit {
		return ListOptions{}, fmt.Errorf("limit must be between 1 and %d", MaxListLimit)
	}
	if opts.Offset < 0 {
		return ListOptions{}, errors.New("offset must be non-negative")
	}
	return opts, nil
}

func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("uuid entropy unavailable")
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:]), nil
}

func ValidateUUID(value, field string) error {
	if value == "" || !uuidRE.MatchString(value) {
		return fmt.Errorf("%s must be a UUID", field)
	}
	return nil
}

func NormalizeEmail(value string) (string, error) {
	if value == "" {
		return "", errors.New("email is required")
	}
	if value != strings.TrimSpace(value) || containsControl(value) {
		return "", errors.New("email contains invalid characters")
	}
	if len(value) > 254 {
		return "", errors.New("email is too long")
	}
	addr, err := mail.ParseAddress(value)
	if err != nil || addr.Name != "" || addr.Address != value {
		return "", errors.New("email is invalid")
	}
	if strings.Count(addr.Address, "@") != 1 {
		return "", errors.New("email is invalid")
	}
	normalized := strings.ToLower(addr.Address)
	if len(normalized) > 254 {
		return "", errors.New("email is too long")
	}
	return normalized, nil
}

func ValidateMachineName(value, field string) error {
	if value == "" || !machineNameRE.MatchString(value) {
		return fmt.Errorf("%s must be a lowercase machine_name", field)
	}
	return nil
}

func ValidateHumanString(value, field string, minLen, maxLen int) error {
	if len(value) < minLen {
		return fmt.Errorf("%s is too short", field)
	}
	if maxLen > 0 && len(value) > maxLen {
		return fmt.Errorf("%s is too long", field)
	}
	if containsControl(value) {
		return fmt.Errorf("%s contains a control character", field)
	}
	return nil
}

func ValidateOptionalHumanString(value *string, field string, maxLen int) error {
	if value == nil {
		return nil
	}
	return ValidateHumanString(*value, field, 0, maxLen)
}

func ValidateTokenHash(value, field string) error {
	if value == "" || !tokenHashRE.MatchString(value) {
		return fmt.Errorf("%s must be a token hash", field)
	}
	return nil
}

func ValidateCorrelationID(value *string) error {
	if value == nil || *value == "" {
		return nil
	}
	if !correlationIDRE.MatchString(*value) {
		return errors.New("correlation_id is invalid")
	}
	return nil
}

func ValidateEncryptedEnvelope(value *string, field string) error {
	if value == nil {
		return nil
	}
	if *value == "" || len(*value) > 8192 || !encryptedEnvelopeRE.MatchString(*value) || containsControl(*value) {
		return fmt.Errorf("%s must be an encrypted database envelope", field)
	}
	return nil
}

func ValidateHTTPSURL(value *string, field string) error {
	if value == nil || *value == "" {
		return nil
	}
	if len(*value) > 2048 || *value != strings.TrimSpace(*value) || containsControl(*value) {
		return fmt.Errorf("%s must be an https_url", field)
	}
	parsed, err := url.Parse(*value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an https_url", field)
	}
	return nil
}

func ValidatePublicHTTPSURL(value *string, field string) error {
	if err := ValidateHTTPSURL(value, field); err != nil {
		return err
	}
	if value == nil || *value == "" {
		return nil
	}
	parsed, err := url.Parse(*value)
	if err != nil {
		return fmt.Errorf("%s must be an https_url", field)
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("%s must be a public https_url", field)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
			return fmt.Errorf("%s must be a public https_url", field)
		}
	}
	return nil
}

func NormalizeTrustedSourceCIDRs(values []string) ([]string, error) {
	if len(values) == 0 {
		return []string{}, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized, err := NormalizeIPOrCIDR(value)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; ok {
			return nil, errors.New("trusted_source_cidrs contains duplicate CIDRs")
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	slices.Sort(out)
	return out, nil
}

func NormalizeIPOrCIDR(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || containsControl(value) {
		return "", errors.New("ip_or_cidr is invalid")
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Is4() {
			return netip.PrefixFrom(addr, 32).Masked().String(), nil
		}
		return netip.PrefixFrom(addr, 128).Masked().String(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", errors.New("ip_or_cidr is invalid")
	}
	return prefix.Masked().String(), nil
}

func NormalizeDomainScopeValue(value string) (string, error) {
	normalized, err := NormalizeCertificateIdentifier(value)
	if err != nil {
		return "", err
	}
	suffix := strings.TrimPrefix(normalized, "*.")
	publicSuffix, _ := publicsuffix.PublicSuffix(suffix)
	if publicSuffix == suffix {
		return "", errors.New("domain scope cannot be a public suffix")
	}
	return normalized, nil
}

func NormalizeCertificateIdentifier(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || containsControl(value) {
		return "", errors.New("certificate identifier is invalid")
	}
	if strings.Count(value, "*") > 0 {
		if !strings.HasPrefix(value, "*.") || strings.Count(value, "*") != 1 {
			return "", errors.New("wildcard domain scope is invalid")
		}
		name, err := NormalizeDNSName(strings.TrimPrefix(value, "*."))
		if err != nil {
			return "", err
		}
		normalized := "*." + name
		if !certificateScopeRE.MatchString(normalized) {
			return "", errors.New("wildcard domain scope is invalid")
		}
		return normalized, nil
	}
	name, err := NormalizeDNSName(value)
	if err != nil {
		return "", err
	}
	if !certificateScopeRE.MatchString(name) {
		return "", errors.New("domain scope is invalid")
	}
	return name, nil
}

func NormalizeDNSName(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || containsControl(value) {
		return "", errors.New("dns_name is invalid")
	}
	if strings.HasSuffix(value, ".") {
		value = strings.TrimSuffix(value, ".")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", errors.New("dns_name is invalid")
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) < 1 || len(ascii) > 253 || strings.HasSuffix(ascii, ".") {
		return "", errors.New("dns_name is invalid")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", errors.New("dns_name must contain at least two labels")
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || !dnsLabelRE.MatchString(label) {
			return "", errors.New("dns_name is invalid")
		}
	}
	return ascii, nil
}

func containsControl(value string) bool {
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) {
			return true
		}
	}
	return false
}
