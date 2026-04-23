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
