// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// helmBinary returns the helm binary, skipping the test when there is none.
func helmBinary(t *testing.T) string {
	t.Helper()
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed; the chart's templates run only under helm")
	}
	return helm
}

// helmTemplate runs `helm template` over charts/gateon with args and returns
// its combined output and error.
func helmTemplate(t *testing.T, helm string, args ...string) (string, error) {
	t.Helper()
	chart := filepath.Join("..", "..", "charts", "gateon")
	full := append([]string{"template", "t", chart}, args...)
	// #nosec G204 -- a test driving the helm binary over this repository's chart.
	out, err := exec.Command(helm, full...).CombinedOutput()
	return string(out), err
}

// fakeKubeAPI answers the requests `helm template --dry-run=server` makes:
// discovery, and a GET for each Secret in secrets (name -> data, unencoded).
// Every other object is NotFound. It records the paths it was asked for.
type fakeKubeAPI struct {
	secrets map[string]map[string]string
	mu      sync.Mutex
	paths   []string
}

func (f *fakeKubeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if body, ok := fakeDiscovery[r.URL.Path]; ok {
		_, _ = fmt.Fprint(w, body)
		return
	}
	const prefix = "/api/v1/namespaces/default/secrets/"
	if name, ok := strings.CutPrefix(r.URL.Path, prefix); ok && r.Method == http.MethodGet {
		if data, found := f.secrets[name]; found {
			_ = json.NewEncoder(w).Encode(secretObject(name, data))
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
}

// fakeDiscovery is the API discovery helm needs to map every kind the chart
// renders to a resource.
var fakeDiscovery = map[string]string{
	"/version": `{"major":"1","minor":"30","gitVersion":"v1.30.0"}`,
	"/api":     `{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[{"clientCIDR":"0.0.0.0/0","serverAddress":"127.0.0.1"}]}`,
	"/apis": `{"kind":"APIGroupList","apiVersion":"v1","groups":[` +
		apiGroup("apps") + `,` + apiGroup("rbac.authorization.k8s.io") + `,` + apiGroup("policy") + `]}`,
	"/api/v1": resourceList("v1", resource("secrets", "Secret"), resource("services", "Service"),
		resource("serviceaccounts", "ServiceAccount")),
	"/apis/apps/v1": resourceList("apps/v1", resource("statefulsets", "StatefulSet")),
	"/apis/rbac.authorization.k8s.io/v1": resourceList("rbac.authorization.k8s.io/v1",
		resource("clusterroles", "ClusterRole"), resource("clusterrolebindings", "ClusterRoleBinding"),
		resource("roles", "Role"), resource("rolebindings", "RoleBinding")),
	"/apis/policy/v1": resourceList("policy/v1", resource("poddisruptionbudgets", "PodDisruptionBudget")),
}

func apiGroup(name string) string {
	gv := name + "/v1"
	return `{"name":"` + name + `","versions":[{"groupVersion":"` + gv + `","version":"v1"}],` +
		`"preferredVersion":{"groupVersion":"` + gv + `","version":"v1"}}`
}

func resource(plural, kind string) string {
	namespaced := kind != "ClusterRole" && kind != "ClusterRoleBinding"
	return fmt.Sprintf(`{"name":%q,"singularName":"","namespaced":%t,"kind":%q,"verbs":["get","list","create"]}`,
		plural, namespaced, kind)
}

func resourceList(gv string, resources ...string) string {
	return `{"kind":"APIResourceList","groupVersion":"` + gv + `","resources":[` + strings.Join(resources, ",") + `]}`
}

func secretObject(name string, data map[string]string) map[string]any {
	enc := map[string]string{}
	for k, v := range data {
		enc[k] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	return map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata": map[string]any{"name": name, "namespace": "default"},
		"data":     enc,
	}
}

// renderedSecretData returns the data of the Secret named name in a rendered
// manifest stream, decoded.
func renderedSecretData(t *testing.T, manifest, name string) map[string]string {
	t.Helper()
	for _, doc := range strings.Split(manifest, "\n---") {
		if !strings.Contains(doc, "kind: Secret") || !strings.Contains(doc, "name: "+name+"\n") {
			continue
		}
		out := map[string]string{}
		inData := false
		for _, line := range strings.Split(doc, "\n") {
			switch {
			case strings.TrimSpace(line) == "data:":
				inData = true
			case inData && strings.HasPrefix(line, "  ") && strings.Contains(line, ": "):
				k, v, _ := strings.Cut(strings.TrimSpace(line), ": ")
				raw, err := base64.StdEncoding.DecodeString(strings.Trim(v, `"`))
				if err != nil {
					t.Fatalf("secret %s key %s is not base64: %v", name, k, err)
				}
				out[k] = string(raw)
			case inData:
				inData = false
			}
		}
		return out
	}
	t.Fatalf("no Secret %s in the rendered chart:\n%s", name, manifest)
	return nil
}

// identityKeys are the Secret keys the chart supplies the gateway's identity
// from (ADR 0056).
var identityKeys = map[string]string{
	"GATEON_SESSION_KEY":         "session-key",
	"GATEON_AUDIT_SIGNATURE_KEY": "audit-signature-key",
	"GATEON_POW_SECRET":          "pow-secret",
}

// TestHelmRefusesMoreThanOneReplica pins OPS-N1's decision (ADR 0056). Each
// replica kept its own global.json, so setup, the audit setting and every
// global setting reached the replica that handled the request and no other;
// the chart allowed it whenever an external database and Redis were set.
func TestHelmRefusesMoreThanOneReplica(t *testing.T) {
	helm := helmBinary(t)
	out, err := helmTemplate(t, helm, "--set", "replicaCount=2",
		"--set", "externalDatabase.enabled=true", "--set", "externalDatabase.host=db",
		"--set", "redis.enabled=true", "--set", "redis.addr=redis:6379")
	if err == nil {
		t.Fatalf("replicaCount=2 with an external database and Redis rendered; want a refusal:\n%.400s", out)
	}
	if !strings.Contains(out, "replicaCount > 1 is not supported") || !strings.Contains(out, "ADR 0056") {
		t.Fatalf("the refusal does not say why:\n%s", out)
	}
	if _, err := helmTemplate(t, helm, "--set", "replicaCount=1"); err != nil {
		t.Fatalf("replicaCount=1 is refused: %v", err)
	}
}

// TestHelmSuppliesTheIdentityFromTheSecret requires every pod to read the
// session key, the audit signature key and the proof-of-work secret from the
// release's Secret. Each was generated per volume, so with persistence off
// every restart was a new gateway: everyone signed out, every 2FA account
// locked out.
func TestHelmSuppliesTheIdentityFromTheSecret(t *testing.T) {
	helm := helmBinary(t)
	out, err := helmTemplate(t, helm, "--set", "persistence.enabled=false")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	data := renderedSecretData(t, out, "t-gateon-secrets")
	for env, key := range identityKeys {
		ref := "- name: " + env + "\n              valueFrom:\n                secretKeyRef:\n" +
			"                  name: t-gateon-secrets\n                  key: " + key + "\n"
		if !strings.Contains(out, ref) {
			t.Errorf("the pod does not read %s from the Secret's %s", env, key)
		}
		if len(data[key]) < 32 {
			t.Errorf("the Secret's %s is %q; want a generated value of at least 32 characters", key, data[key])
		}
	}
	if got := len(data["session-key"]); got != 32 {
		t.Errorf("session-key is %d characters; gateon uses exactly the first 32", got)
	}
	if strings.Contains(out, "optional: true") {
		t.Error("an identity key is optional on a chart-created Secret with persistence off")
	}
}

// TestHelmKeepsTheIdentityOnUpgrade drives the chart's lookup against a fake
// API server holding the release's Secret, as `helm upgrade` sees it. A
// regenerated session key signs everyone out and strands every second factor;
// a regenerated audit key fails the whole stored chain's verification. A
// Secret from before the identity keys existed gets them generated once.
func TestHelmKeepsTheIdentityOnUpgrade(t *testing.T) {
	helm := helmBinary(t)
	existing := map[string]string{
		"encryption-key":      "existing-encryption-key-0123456789",
		"session-key":         "existing-session-key-0123456789ab",
		"audit-signature-key": "existing-audit-signature-key-0123456789abcdef",
		"pow-secret":          "existing-pow-secret-0123456789abcdef0123",
	}
	for _, tc := range []struct {
		name string
		held map[string]string
	}{
		{"all keys held", existing},
		{"a pre-identity Secret", map[string]string{"encryption-key": existing["encryption-key"]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeKubeAPI{secrets: map[string]map[string]string{"t-gateon-secrets": tc.held}}
			srv := httptest.NewServer(api)
			defer srv.Close()
			out, err := helmTemplate(t, helm, "--is-upgrade", "--dry-run=server", "--kube-apiserver", srv.URL,
				"--namespace", "default", "--disable-openapi-validation")
			if err != nil {
				t.Fatalf("helm template against the fake API: %v\n%s", err, out)
			}
			api.mu.Lock()
			asked := strings.Join(api.paths, "\n")
			api.mu.Unlock()
			if !strings.Contains(asked, "GET /api/v1/namespaces/default/secrets/t-gateon-secrets") {
				t.Fatalf("helm never looked the Secret up, so this proves nothing; it asked for:\n%s", asked)
			}
			data := renderedSecretData(t, out, "t-gateon-secrets")
			for key, want := range tc.held {
				if data[key] != want {
					t.Errorf("%s = %q on upgrade; want the existing %q", key, data[key], want)
				}
			}
			for _, key := range identityKeys {
				if len(data[key]) < 32 {
					t.Errorf("%s = %q; want one generated where the Secret had none", key, data[key])
				}
			}
		})
	}
}
