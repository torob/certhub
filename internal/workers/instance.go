package workers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	instanceRandomBytes     = 8
	instanceHostnameMaxLen  = 40
	maxWorkerIDLength       = 255
	maxInstanceIDLength     = 80
	instanceIDFormatMessage = "worker instance ID must be 1-80 lowercase letters, digits, or hyphens and start with a letter or digit"
)

var (
	instanceIDRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	instanceHostnameRE = regexp.MustCompile(`[^a-z0-9-]+`)
)

// NewInstanceID returns an identifier that is unique to one server process.
// Every worker ID of the process includes it, so job leases fenced by
// locked_by cannot be shared by workers of different replicas. The optional
// hostname prefix only helps operators; the random suffix gives uniqueness.
func NewInstanceID() (string, error) {
	random := make([]byte, instanceRandomBytes)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate worker instance ID: %w", err)
	}
	suffix := hex.EncodeToString(random)
	hostname, _ := os.Hostname()
	if host := sanitizeInstanceHostname(hostname); host != "" {
		return host + "-" + suffix, nil
	}
	return suffix, nil
}

func sanitizeInstanceHostname(hostname string) string {
	host := instanceHostnameRE.ReplaceAllString(strings.ToLower(hostname), "-")
	host = strings.Trim(host, "-")
	if len(host) > instanceHostnameMaxLen {
		host = strings.Trim(host[:instanceHostnameMaxLen], "-")
	}
	return host
}

// workerIDs builds the IDs "<prefix>-<instance>-<n>" for count workers. It
// generates a new instance ID when instanceID is empty.
func workerIDs(prefix, instanceID string, count int) ([]string, error) {
	if instanceID == "" {
		generated, err := NewInstanceID()
		if err != nil {
			return nil, err
		}
		instanceID = generated
	}
	if len(instanceID) > maxInstanceIDLength || !instanceIDRE.MatchString(instanceID) {
		return nil, errors.New(instanceIDFormatMessage)
	}
	ids := make([]string, count)
	for i := range ids {
		id := fmt.Sprintf("%s-%s-%d", prefix, instanceID, i+1)
		if len(id) > maxWorkerIDLength {
			return nil, fmt.Errorf("worker ID must be at most %d characters", maxWorkerIDLength)
		}
		ids[i] = id
	}
	return ids, nil
}
