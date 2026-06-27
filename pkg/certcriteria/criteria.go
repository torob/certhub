package certcriteria

import (
	"errors"
	"slices"

	"certhub/internal/storage"
)

const DefaultKeyType = "ecdsa-p256"

type Criteria struct {
	Domains []string
	KeyType string
	Issuer  string
}

type Normalized struct {
	Domains []string
	KeyType string
	Issuer  string
}

func Normalize(criteria Criteria) (Normalized, error) {
	if len(criteria.Domains) == 0 {
		return Normalized{}, errors.New("domains are required")
	}
	seen := map[string]struct{}{}
	domains := make([]string, 0, len(criteria.Domains))
	for _, domain := range criteria.Domains {
		normalized, err := storage.NormalizeCertificateIdentifier(domain)
		if err != nil {
			return Normalized{}, err
		}
		if _, ok := seen[normalized]; ok {
			return Normalized{}, errors.New("domains must be unique")
		}
		seen[normalized] = struct{}{}
		domains = append(domains, normalized)
	}
	slices.Sort(domains)
	keyType := criteria.KeyType
	if keyType == "" {
		keyType = DefaultKeyType
	}
	switch keyType {
	case "rsa-2048", "rsa-3072", "rsa-4096", "ecdsa-p256", "ecdsa-p384":
	default:
		return Normalized{}, errors.New("key_type is invalid")
	}
	if criteria.Issuer != "" {
		if err := storage.ValidateMachineName(criteria.Issuer, "issuer"); err != nil {
			return Normalized{}, err
		}
	}
	return Normalized{Domains: domains, KeyType: keyType, Issuer: criteria.Issuer}, nil
}
