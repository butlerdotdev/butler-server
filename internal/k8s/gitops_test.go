/*
Copyright 2026 The Butler Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package k8s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// kubeconfigFromRESTConfig must produce kubeconfig bytes that `flux bootstrap`
// and other kubeconfig-consuming tools can load. The test pins the output
// shape: valid YAML, single context, CA bundle embedded as data (not a file
// path), SA token preserved. Regression guard for the GetManagementKubeconfig
// in-cluster fallback.

func TestKubeconfigFromRESTConfig_RoundTrip(t *testing.T) {
	cfg := &rest.Config{
		Host:        "https://apiserver.butler-system.svc:6443",
		BearerToken: "eyJhbGc.sa-token.sig",
		TLSClientConfig: rest.TLSClientConfig{
			CAData: []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"),
		},
	}

	data, err := kubeconfigFromRESTConfig(cfg)
	if err != nil {
		t.Fatalf("kubeconfigFromRESTConfig: %v", err)
	}

	apiCfg, err := clientcmd.Load(data)
	if err != nil {
		t.Fatalf("emitted bytes do not parse as kubeconfig: %v", err)
	}

	if apiCfg.CurrentContext != "in-cluster" {
		t.Errorf("current-context = %q, want in-cluster", apiCfg.CurrentContext)
	}
	cluster, ok := apiCfg.Clusters["in-cluster"]
	if !ok {
		t.Fatal("in-cluster cluster missing")
	}
	if cluster.Server != cfg.Host {
		t.Errorf("server = %q, want %q", cluster.Server, cfg.Host)
	}
	if string(cluster.CertificateAuthorityData) != string(cfg.CAData) {
		t.Errorf("CA data round-trip failed")
	}
	if cluster.CertificateAuthority != "" {
		t.Error("expected inline CAData, not a file path reference")
	}

	authInfo, ok := apiCfg.AuthInfos["in-cluster"]
	if !ok {
		t.Fatal("in-cluster authinfo missing")
	}
	if authInfo.Token != cfg.BearerToken {
		t.Errorf("token did not round-trip")
	}
}

func TestKubeconfigFromRESTConfig_LoadsCAFromFile(t *testing.T) {
	// rest.InClusterConfig() returns CAFile set + CAData empty. The synthesis
	// must promote the file bytes into CertificateAuthorityData so downstream
	// consumers that build their own transport can verify the apiserver cert.
	// Regression guard for the v0.7.1 hotfix.
	caBytes := []byte("-----BEGIN CERTIFICATE-----\nMIIBfiletest\n-----END CERTIFICATE-----\n")
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(caPath, caBytes, 0o600); err != nil {
		t.Fatalf("write test CA file: %v", err)
	}

	cfg := &rest.Config{
		Host:        "https://10.96.0.1:443",
		BearerToken: "sa-token",
		TLSClientConfig: rest.TLSClientConfig{
			CAFile: caPath,
		},
	}

	data, err := kubeconfigFromRESTConfig(cfg)
	if err != nil {
		t.Fatalf("kubeconfigFromRESTConfig: %v", err)
	}

	apiCfg, err := clientcmd.Load(data)
	if err != nil {
		t.Fatalf("emitted bytes do not parse as kubeconfig: %v", err)
	}
	cluster := apiCfg.Clusters["in-cluster"]
	if cluster == nil {
		t.Fatal("in-cluster cluster missing")
	}
	if string(cluster.CertificateAuthorityData) != string(caBytes) {
		t.Errorf("CertificateAuthorityData = %q, want the CAFile contents %q", cluster.CertificateAuthorityData, caBytes)
	}
	if cluster.CertificateAuthority != "" {
		t.Error("expected CAData only, not a file path reference")
	}
}

func TestKubeconfigFromRESTConfig_CAFileMissing(t *testing.T) {
	// If CAFile is set but unreadable, return an error rather than emitting a
	// kubeconfig with no CA (which silently reproduces the bug we are fixing).
	cfg := &rest.Config{
		Host:        "https://10.96.0.1:443",
		BearerToken: "sa-token",
		TLSClientConfig: rest.TLSClientConfig{
			CAFile: "/tmp/definitely-does-not-exist/ca.crt",
		},
	}
	data, err := kubeconfigFromRESTConfig(cfg)
	if err == nil {
		t.Fatalf("expected error when CAFile is missing, got data: %q", data)
	}
	if !strings.Contains(err.Error(), "read CA file") {
		t.Errorf("error = %q, want it to mention CA file", err.Error())
	}
}

func TestKubeconfigFromRESTConfig_EmptyToken(t *testing.T) {
	cfg := &rest.Config{
		Host:        "https://apiserver:6443",
		BearerToken: "",
	}
	data, err := kubeconfigFromRESTConfig(cfg)
	if err != nil {
		t.Fatalf("kubeconfigFromRESTConfig: %v", err)
	}
	if _, err := clientcmd.Load(data); err != nil {
		t.Fatalf("expected parseable output, got: %v", err)
	}
	if !strings.Contains(string(data), "in-cluster") {
		t.Error("expected in-cluster context name in output")
	}
}
