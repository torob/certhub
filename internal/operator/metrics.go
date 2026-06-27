package operator

import (
	"fmt"
	"net/http"
	"sync"
)

type Metrics struct {
	mu               sync.Mutex
	reconciles       map[string]int64
	durationCount    int64
	durationSum      float64
	backendByCode    map[string]int64
	secretSyncs      map[string]int64
	conditionCurrent map[conditionMetricKey]int64
}

type conditionMetricKey struct {
	Namespace string
	Name      string
	Condition string
}

func NewMetrics() *Metrics {
	return &Metrics{
		reconciles:       map[string]int64{},
		backendByCode:    map[string]int64{},
		secretSyncs:      map[string]int64{},
		conditionCurrent: map[conditionMetricKey]int64{},
	}
}

func (m *Metrics) IncReconcile(result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconciles[result]++
}

func (m *Metrics) ObserveReconcileDuration(durationSeconds float64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.durationCount++
	m.durationSum += durationSeconds
}

func (m *Metrics) IncBackend(code string) {
	if m == nil {
		return
	}
	if code == "" {
		code = "ok"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.backendByCode[code]++
}

func (m *Metrics) IncSecretSync(result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secretSyncs[result]++
}

func (m *Metrics) SetResourceCondition(namespace, name, condition string, value bool) {
	if m == nil {
		return
	}
	v := int64(0)
	if value {
		v = 1
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conditionCurrent[conditionMetricKey{Namespace: namespace, Name: name, Condition: condition}] = v
}

func (m *Metrics) SetCertificateConditions(cert *CerthubCertificate) {
	if m == nil || cert == nil {
		return
	}
	for _, condition := range cert.Status.Conditions {
		m.SetResourceCondition(cert.Metadata.Namespace, cert.Metadata.Name, condition.Type, condition.Status == ConditionTrue)
	}
}

func (m *Metrics) ClearCertificateConditions(namespace, name string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.conditionCurrent {
		if key.Namespace == namespace && key.Name == name {
			delete(m.conditionCurrent, key)
		}
	}
}

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		if m == nil {
			return
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		for result, value := range m.reconciles {
			fmt.Fprintf(w, "certhub_operator_reconcile_total{result=%q} %d\n", result, value)
		}
		fmt.Fprintf(w, "certhub_operator_reconcile_duration_seconds_count %d\n", m.durationCount)
		fmt.Fprintf(w, "certhub_operator_reconcile_duration_seconds_sum %.6f\n", m.durationSum)
		for code, value := range m.backendByCode {
			fmt.Fprintf(w, "certhub_operator_backend_requests_total{code=%q} %d\n", code, value)
		}
		for result, value := range m.secretSyncs {
			fmt.Fprintf(w, "certhub_operator_secret_sync_total{result=%q} %d\n", result, value)
		}
		for key, value := range m.conditionCurrent {
			fmt.Fprintf(w, "certhub_operator_condition{namespace=%q,name=%q,condition=%q} %d\n", key.Namespace, key.Name, key.Condition, value)
		}
	})
}
