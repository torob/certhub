package applications

import (
	"strings"

	"certhub/internal/storage"
)

type DomainCoverageResult struct {
	NormalizedIdentifiers []string
	UncoveredIdentifiers  []string
}

func NormalizeCertificateIdentifier(value string) (string, error) {
	return storage.NormalizeCertificateIdentifier(value)
}

func NormalizeDomainScope(value string) (string, error) {
	return storage.NormalizeDomainScopeValue(value)
}

func ScopeCoversIdentifier(scopeValue, identifier string) (bool, error) {
	scope, err := NormalizeDomainScope(scopeValue)
	if err != nil {
		return false, err
	}
	normalized, err := NormalizeCertificateIdentifier(identifier)
	if err != nil {
		return false, err
	}
	return normalizedScopeCoversIdentifier(scope, normalized), nil
}

func ScopesCoverIdentifiers(scopes []DomainScope, identifiers []string) (DomainCoverageResult, error) {
	result := DomainCoverageResult{
		NormalizedIdentifiers: make([]string, 0, len(identifiers)),
	}
	for _, identifier := range identifiers {
		normalized, err := NormalizeCertificateIdentifier(identifier)
		if err != nil {
			return DomainCoverageResult{}, err
		}
		result.NormalizedIdentifiers = append(result.NormalizedIdentifiers, normalized)
		covered := false
		for _, scope := range scopes {
			if normalizedScopeCoversIdentifier(scope.Value, normalized) {
				covered = true
				break
			}
		}
		if !covered {
			result.UncoveredIdentifiers = append(result.UncoveredIdentifiers, normalized)
		}
	}
	return result, nil
}

func normalizedScopeCoversIdentifier(scope, identifier string) bool {
	if scope == identifier {
		return true
	}
	if strings.HasPrefix(identifier, "*.") {
		return false
	}
	if !strings.HasPrefix(scope, "*.") {
		return false
	}
	base := strings.TrimPrefix(scope, "*.")
	if !strings.HasSuffix(identifier, "."+base) {
		return false
	}
	return labelCount(identifier) == labelCount(base)+1
}

func labelCount(value string) int {
	if value == "" {
		return 0
	}
	return strings.Count(value, ".") + 1
}
