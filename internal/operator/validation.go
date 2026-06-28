package operator

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/torob/certhub/pkg/certcriteria"
)

var secretNameRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func ValidateCertificateSpec(spec CerthubCertificateSpec) (certcriteria.Normalized, error) {
	for field, value := range map[string]string{
		"secretName":           spec.SecretName,
		"keyType":              spec.KeyType,
		"issuer":               spec.Issuer,
		"secretDeletionPolicy": spec.SecretDeletionPolicy,
	} {
		if value == "" {
			continue
		}
		if value != strings.TrimSpace(value) || containsControl(value) {
			return certcriteria.Normalized{}, fmt.Errorf("%s contains invalid characters", field)
		}
	}
	for i, domain := range spec.Domains {
		if domain == "" || domain != strings.TrimSpace(domain) || containsControl(domain) {
			return certcriteria.Normalized{}, fmt.Errorf("domains[%d] contains invalid characters", i)
		}
	}
	if spec.SecretName == "" || !secretNameRE.MatchString(spec.SecretName) {
		return certcriteria.Normalized{}, errors.New("secretName must be a Kubernetes DNS label")
	}
	policy := SecretDeletionPolicy(spec)
	if policy != PolicyRetain && policy != PolicyDelete {
		return certcriteria.Normalized{}, errors.New("secretDeletionPolicy must be Retain or Delete")
	}
	return certcriteria.Normalize(certcriteria.Criteria{
		Domains: spec.Domains,
		KeyType: spec.KeyType,
		Issuer:  spec.Issuer,
	})
}

func SecretDeletionPolicy(spec CerthubCertificateSpec) string {
	if spec.SecretDeletionPolicy == "" {
		return PolicyRetain
	}
	return spec.SecretDeletionPolicy
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
