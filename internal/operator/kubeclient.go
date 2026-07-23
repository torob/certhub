package operator

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/torob/certhub/pkg/netretry"
)

const (
	serviceAccountDir       = "/var/run/secrets/kubernetes.io/serviceaccount"
	serviceAccountTokenFile = serviceAccountDir + "/token"
	serviceAccountCAFile    = serviceAccountDir + "/ca.crt"
	serviceAccountNSFile    = serviceAccountDir + "/namespace"
)

type CertificateLister interface {
	ListCertificates(ctx context.Context, namespace string) ([]*CerthubCertificate, error)
}

type CertificateWatcher interface {
	WatchCertificateChanges(ctx context.Context, namespace string) (<-chan CertificateWatchEvent, error)
}

type CertificateWatchEvent struct {
	Type        string
	Certificate *CerthubCertificate
}

type RESTKubeClient struct {
	baseURL          string
	token            string
	defaultNamespace string
	httpClient       *http.Client
	retry            netretry.Policy
	client           netretry.Doer
}

func NewInClusterRESTKubeClient() (*RESTKubeClient, error) {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" || port == "" {
		return nil, errors.New("Kubernetes service environment is not available")
	}
	tokenBytes, err := os.ReadFile(serviceAccountTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}
	namespaceBytes, _ := os.ReadFile(serviceAccountNSFile)
	caPool, err := x509.SystemCertPool()
	if err != nil || caPool == nil {
		caPool = x509.NewCertPool()
	}
	if caBytes, err := os.ReadFile(serviceAccountCAFile); err == nil {
		caPool.AppendCertsFromPEM(caBytes)
	}
	return &RESTKubeClient{
		baseURL:          "https://" + netJoinHostPort(host, port),
		token:            strings.TrimSpace(string(tokenBytes)),
		defaultNamespace: strings.TrimSpace(string(namespaceBytes)),
		httpClient: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    caPool,
		}}, Timeout: 30 * time.Second},
		retry: netretry.DefaultPolicy(),
	}, nil
}

func (c *RESTKubeClient) DefaultNamespace() string {
	if c == nil {
		return ""
	}
	return c.defaultNamespace
}

func (c *RESTKubeClient) GetSecret(ctx context.Context, namespace, name string) (*Secret, error) {
	namespace = c.resolveNamespace(namespace)
	var secret Secret
	if err := c.do(ctx, http.MethodGet, coreNamespacedPath(namespace, "secrets", name), nil, &secret, http.StatusOK); err != nil {
		return nil, err
	}
	return &secret, nil
}

func (c *RESTKubeClient) CreateOrUpdateSecret(ctx context.Context, secret *Secret) error {
	if secret == nil {
		return errors.New("Secret is required")
	}
	secret.APIVersion = "v1"
	secret.Kind = "Secret"
	existing, err := c.GetSecret(ctx, secret.Metadata.Namespace, secret.Metadata.Name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return c.do(ctx, http.MethodPost, coreNamespacedPath(secret.Metadata.Namespace, "secrets", ""), secret, nil, http.StatusCreated, http.StatusOK)
		}
		return err
	}
	if err := checkWritableExistingSecret(existing, secret); err != nil {
		return err
	}
	secret.Metadata.ResourceVersion = existing.Metadata.ResourceVersion
	return c.do(ctx, http.MethodPut, coreNamespacedPath(secret.Metadata.Namespace, "secrets", secret.Metadata.Name), secret, nil, http.StatusOK)
}

func (c *RESTKubeClient) SetSecretOwnerReferences(ctx context.Context, secret *Secret, ownerReferences []OwnerReference) error {
	if secret == nil {
		return errors.New("Secret is required")
	}
	if secret.Metadata.ResourceVersion == "" {
		return errors.New("set Secret owner references requires resourceVersion")
	}
	namespace := c.resolveNamespace(secret.Metadata.Namespace)
	body := map[string]any{"metadata": map[string]any{
		"resourceVersion": secret.Metadata.ResourceVersion,
		"ownerReferences": ownerReferences,
	}}
	var updated Secret
	if err := c.doPatch(ctx, coreNamespacedPath(namespace, "secrets", secret.Metadata.Name), body, &updated, http.StatusOK); err != nil {
		return err
	}
	if err := validateSecretOwnerReferencePatchResponse(secret, &updated, ownerReferences); err != nil {
		return err
	}
	secret.Metadata.ResourceVersion = updated.Metadata.ResourceVersion
	secret.Metadata.OwnerReferences = append([]OwnerReference(nil), updated.Metadata.OwnerReferences...)
	return nil
}

func (c *RESTKubeClient) DeleteSecret(ctx context.Context, namespace, name string, expected *Secret) error {
	namespace = c.resolveNamespace(namespace)
	existing, err := c.GetSecret(ctx, namespace, name)
	if err != nil {
		return err
	}
	if expected == nil {
		return errors.New("delete requires expected Secret ownership")
	}
	if err := checkWritableExistingSecret(existing, expected); err != nil {
		return err
	}
	body := map[string]any{
		"apiVersion": "v1",
		"kind":       "DeleteOptions",
		"preconditions": map[string]any{
			"uid":             existing.Metadata.UID,
			"resourceVersion": existing.Metadata.ResourceVersion,
		},
	}
	if err := c.do(ctx, http.MethodDelete, coreNamespacedPath(namespace, "secrets", name), body, nil, http.StatusOK, http.StatusAccepted, http.StatusNoContent); err != nil {
		return err
	}
	remaining, err := c.GetSecret(ctx, namespace, name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("confirm Secret deletion: %w", err)
	}
	if remaining.Metadata.UID != existing.Metadata.UID {
		return fmt.Errorf("confirm Secret deletion: replacement Secret has UID %q, expected deleted UID %q", remaining.Metadata.UID, existing.Metadata.UID)
	}
	return fmt.Errorf("%w: Secret %s/%s with UID %q still exists", ErrDeletionPending, namespace, name, existing.Metadata.UID)
}

func (c *RESTKubeClient) UpdateStatus(ctx context.Context, cert *CerthubCertificate) error {
	body := map[string]any{
		"apiVersion": APIVersion,
		"kind":       Kind,
		"metadata": map[string]any{
			"name":            cert.Metadata.Name,
			"namespace":       cert.Metadata.Namespace,
			"resourceVersion": cert.Metadata.ResourceVersion,
		},
		"status": cert.Status,
	}
	return c.do(ctx, http.MethodPut, crPath(cert.Metadata.Namespace, cert.Metadata.Name)+"/status", body, nil, http.StatusOK)
}

func (c *RESTKubeClient) UpdateFinalizers(ctx context.Context, cert *CerthubCertificate, finalizers []string) error {
	body := map[string]any{"metadata": map[string]any{
		"resourceVersion": cert.Metadata.ResourceVersion,
		"finalizers":      finalizers,
	}}
	var updated CerthubCertificate
	if err := c.doPatch(ctx, crPath(cert.Metadata.Namespace, cert.Metadata.Name), body, &updated, http.StatusOK); err != nil {
		return err
	}
	if updated.Metadata.ResourceVersion == "" {
		return errors.New("Kubernetes finalizer patch response is missing resourceVersion")
	}
	if !equalStringMultiset(updated.Metadata.Finalizers, finalizers) {
		return fmt.Errorf("Kubernetes finalizer patch response does not match requested finalizers: requested=%q returned=%q", finalizers, updated.Metadata.Finalizers)
	}
	cert.Metadata.ResourceVersion = updated.Metadata.ResourceVersion
	cert.Metadata.Finalizers = append([]string(nil), updated.Metadata.Finalizers...)
	return nil
}

func validateSecretOwnerReferencePatchResponse(before, updated *Secret, requested []OwnerReference) error {
	if updated.Metadata.ResourceVersion == "" {
		return errors.New("Kubernetes Secret owner-reference patch response is missing resourceVersion")
	}
	if !equalOwnerReferenceMultiset(updated.Metadata.OwnerReferences, requested) {
		return fmt.Errorf("Kubernetes Secret owner-reference patch response does not match requested owner references")
	}
	if updated.Metadata.Name != before.Metadata.Name ||
		updated.Metadata.Namespace != before.Metadata.Namespace ||
		updated.Metadata.UID != before.Metadata.UID ||
		updated.Metadata.Generation != before.Metadata.Generation ||
		!equalTimes(updated.Metadata.CreationTimestamp, before.Metadata.CreationTimestamp) ||
		!reflect.DeepEqual(updated.Metadata.Labels, before.Metadata.Labels) ||
		!reflect.DeepEqual(updated.Metadata.Annotations, before.Metadata.Annotations) ||
		!equalStringMultiset(updated.Metadata.Finalizers, before.Metadata.Finalizers) ||
		!equalTimes(updated.Metadata.DeletionTimestamp, before.Metadata.DeletionTimestamp) ||
		updated.Type != before.Type ||
		!reflect.DeepEqual(updated.Data, before.Data) {
		return errors.New("Kubernetes Secret owner-reference patch response changed fields outside ownerReferences/resourceVersion")
	}
	return nil
}

func equalStringMultiset(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

func equalOwnerReferenceMultiset(left, right []OwnerReference) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[OwnerReference]int, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	return true
}

func equalTimes(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func (c *RESTKubeClient) EmitEvent(ctx context.Context, event Event) error {
	now := time.Now().UTC().Format(time.RFC3339)
	body := map[string]any{
		"apiVersion": "v1",
		"kind":       "Event",
		"metadata": map[string]any{
			"generateName": "certhub-operator-",
			"namespace":    event.Namespace,
		},
		"involvedObject": map[string]any{
			"apiVersion": APIVersion,
			"kind":       Kind,
			"name":       event.Name,
			"namespace":  event.Namespace,
		},
		"type":           event.Type,
		"reason":         event.Reason,
		"message":        event.Message,
		"source":         map[string]any{"component": "certhub-operator"},
		"firstTimestamp": now,
		"lastTimestamp":  now,
		"count":          1,
	}
	return c.do(ctx, http.MethodPost, coreNamespacedPath(event.Namespace, "events", ""), body, nil, http.StatusCreated, http.StatusOK)
}

func (c *RESTKubeClient) ListCertificates(ctx context.Context, namespace string) ([]*CerthubCertificate, error) {
	var list struct {
		Items []CerthubCertificate `json:"items"`
	}
	listPath := "/apis/" + APIGroup + "/v1alpha1/certhubcertificates"
	if namespace != "" {
		listPath = "/apis/" + APIGroup + "/v1alpha1/namespaces/" + url.PathEscape(namespace) + "/certhubcertificates"
	}
	if err := c.do(ctx, http.MethodGet, listPath, nil, &list, http.StatusOK); err != nil {
		return nil, err
	}
	out := make([]*CerthubCertificate, 0, len(list.Items))
	for i := range list.Items {
		item := list.Items[i]
		out = append(out, &item)
	}
	return out, nil
}

func (c *RESTKubeClient) WatchCertificateChanges(ctx context.Context, namespace string) (<-chan CertificateWatchEvent, error) {
	ch := make(chan CertificateWatchEvent, 16)
	go func() {
		defer close(ch)
		for ctx.Err() == nil {
			watchPath := "/apis/" + APIGroup + "/v1alpha1/certhubcertificates?watch=true"
			if namespace != "" {
				watchPath = "/apis/" + APIGroup + "/v1alpha1/namespaces/" + url.PathEscape(namespace) + "/certhubcertificates?watch=true"
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+watchPath, nil)
			if err != nil {
				return
			}
			req.Header.Set("Accept", "application/json")
			if c.token != "" {
				req.Header.Set("Authorization", "Bearer "+c.token)
			}
			resp, err := c.retryClient().Do(req)
			if err != nil {
				sleepWatchRetry(ctx)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				sleepWatchRetry(ctx)
				continue
			}
			dec := json.NewDecoder(resp.Body)
			for ctx.Err() == nil {
				var envelope struct {
					Type   string          `json:"type"`
					Object json.RawMessage `json:"object"`
				}
				if err := dec.Decode(&envelope); err != nil {
					break
				}
				switch envelope.Type {
				case "ADDED", "MODIFIED", "DELETED":
				default:
					continue
				}
				var cert CerthubCertificate
				if err := json.Unmarshal(envelope.Object, &cert); err != nil {
					continue
				}
				select {
				case ch <- CertificateWatchEvent{Type: envelope.Type, Certificate: &cert}:
				case <-ctx.Done():
					_ = resp.Body.Close()
					return
				}
			}
			_ = resp.Body.Close()
			sleepWatchRetry(ctx)
		}
	}()
	return ch, nil
}

func sleepWatchRetry(ctx context.Context) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (c *RESTKubeClient) do(ctx context.Context, method, requestPath string, body any, out any, okStatuses ...int) error {
	return c.doWithContentType(ctx, method, requestPath, "application/json", body, out, okStatuses...)
}

func (c *RESTKubeClient) doPatch(ctx context.Context, requestPath string, body any, out any, okStatuses ...int) error {
	return c.doWithContentType(ctx, http.MethodPatch, requestPath, "application/merge-patch+json", body, out, okStatuses...)
}

func (c *RESTKubeClient) doWithContentType(ctx context.Context, method, requestPath, contentType string, body any, out any, okStatuses ...int) error {
	if c == nil || c.httpClient == nil {
		return errors.New("Kubernetes REST client is not configured")
	}
	var payload io.Reader
	if body != nil {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(body); err != nil {
			return fmt.Errorf("encode Kubernetes request: %w", err)
		}
		payload = &buf
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+requestPath, payload)
	if err != nil {
		return fmt.Errorf("build Kubernetes request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.retryClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, resp.Body)
		return ErrNotFound
	}
	for _, ok := range okStatuses {
		if resp.StatusCode == ok {
			if out != nil {
				return json.NewDecoder(resp.Body).Decode(out)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			return nil
		}
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("Kubernetes API %s %s failed: status=%d body=%s", method, requestPath, resp.StatusCode, Sanitize(string(data)))
}

func (c *RESTKubeClient) retryClient() netretry.Doer {
	if c.client != nil {
		return c.client
	}
	return netretry.NewClient(c.httpClient, c.retry)
}

func (c *RESTKubeClient) resolveNamespace(namespace string) string {
	if namespace != "" {
		return namespace
	}
	return c.defaultNamespace
}

func coreNamespacedPath(namespace, resource, name string) string {
	p := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/" + resource
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p
}

func crPath(namespace, name string) string {
	return "/apis/" + APIGroup + "/v1alpha1/namespaces/" + url.PathEscape(namespace) + "/certhubcertificates/" + url.PathEscape(name)
}

func netJoinHostPort(host, port string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
