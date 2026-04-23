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
	"context"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// ButlerConfigGVR is the GroupVersionResource for ButlerConfig.
var ButlerConfigGVR = schema.GroupVersionResource{
	Group:    "butler.butlerlabs.dev",
	Version:  "v1alpha1",
	Resource: "butlerconfigs",
}

// GetConfigMap retrieves a ConfigMap's data.
func (c *Client) GetConfigMap(ctx context.Context, namespace, name string) (map[string]string, error) {
	cm, err := c.clientset.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return cm.Data, nil
}

// CreateOrUpdateConfigMap creates or updates a ConfigMap.
func (c *Client) CreateOrUpdateConfigMap(ctx context.Context, namespace, name string, data map[string]string) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "butler",
				"app.kubernetes.io/component":  "gitops",
			},
		},
		Data: data,
	}

	existing, err := c.clientset.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = c.clientset.CoreV1().ConfigMaps(namespace).Create(ctx, cm, metav1.CreateOptions{})
			return err
		}
		return err
	}

	if existing.Labels != nil {
		for k, v := range existing.Labels {
			if _, exists := cm.Labels[k]; !exists {
				cm.Labels[k] = v
			}
		}
	}
	cm.ResourceVersion = existing.ResourceVersion

	_, err = c.clientset.CoreV1().ConfigMaps(namespace).Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// DeleteConfigMap deletes a ConfigMap.
func (c *Client) DeleteConfigMap(ctx context.Context, namespace, name string) error {
	return c.clientset.CoreV1().ConfigMaps(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

// GetSecretValue retrieves a single value from a Secret.
func (c *Client) GetSecretValue(ctx context.Context, namespace, name, key string) (string, error) {
	secret, err := c.clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", key, namespace, name)
	}

	return string(value), nil
}

// CreateOrUpdateSecret creates or updates a Secret.
func (c *Client) CreateOrUpdateSecret(ctx context.Context, namespace, name string, data map[string][]byte) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "butler",
				"app.kubernetes.io/component":  "gitops",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}

	existing, err := c.clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = c.clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
			return err
		}
		return err
	}

	secret.ResourceVersion = existing.ResourceVersion
	_, err = c.clientset.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

// DeleteSecret deletes a Secret.
func (c *Client) DeleteSecret(ctx context.Context, namespace, name string) error {
	return c.clientset.CoreV1().Secrets(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

// GetTenantKubeconfig retrieves the kubeconfig for a tenant cluster.
func (c *Client) GetTenantKubeconfig(ctx context.Context, namespace, name string) ([]byte, error) {
	tc, err := c.GetTenantCluster(ctx, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get TenantCluster: %w", err)
	}

	tenantNS, found, err := unstructured.NestedString(tc.Object, "status", "tenantNamespace")
	if err != nil || !found || tenantNS == "" {
		return nil, fmt.Errorf("tenant namespace not found in TenantCluster status")
	}

	secretNames := []string{
		fmt.Sprintf("%s-admin-kubeconfig", name),
		fmt.Sprintf("%s-kubeconfig", name),
	}

	var secret *corev1.Secret
	for _, secretName := range secretNames {
		secret, err = c.clientset.CoreV1().Secrets(tenantNS).Get(ctx, secretName, metav1.GetOptions{})
		if err == nil {
			break
		}
	}

	if secret == nil {
		return nil, fmt.Errorf("kubeconfig secret not found for cluster %s/%s (tried namespace %s)", namespace, name, tenantNS)
	}

	keyPatterns := []string{"admin.conf", "super-admin.conf", "value", "kubeconfig"}
	for _, key := range keyPatterns {
		if data, ok := secret.Data[key]; ok {
			return data, nil
		}
	}

	return nil, fmt.Errorf("kubeconfig data not found in secret (tried keys: %v)", keyPatterns)
}

// GetTenantKubeconfigAsString retrieves the kubeconfig as a string.
func (c *Client) GetTenantKubeconfigAsString(ctx context.Context, namespace, name string) (string, error) {
	data, err := c.GetTenantKubeconfig(ctx, namespace, name)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetManagementKubeconfig returns the kubeconfig for the management cluster.
// Fallback chain: KUBECONFIG env, ~/.kube/config, in-cluster config synthesized
// into kubeconfig bytes. The in-cluster synthesis path is the production case:
// when butler-server runs as a pod in butler-system, no kubeconfig file exists
// but the pod's ServiceAccount token is mounted and is what flux bootstrap needs.
func (c *Client) GetManagementKubeconfig() ([]byte, error) {
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		if homeDir, err := os.UserHomeDir(); err == nil {
			kubeconfigPath = homeDir + "/.kube/config"
		}
	}
	if kubeconfigPath != "" {
		if data, err := os.ReadFile(kubeconfigPath); err == nil {
			return data, nil
		}
	}
	return synthesizeInClusterKubeconfig()
}

// synthesizeInClusterKubeconfig builds kubeconfig bytes from the in-cluster
// rest.Config. The output is a minimal single-context kubeconfig suitable for
// tools like `flux bootstrap` that expect a kubeconfig file path.
func synthesizeInClusterKubeconfig() ([]byte, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("file kubeconfig and in-cluster config both unavailable: %w", err)
	}
	kc := clientcmdapi.Config{
		APIVersion:     "v1",
		Kind:           "Config",
		CurrentContext: "in-cluster",
		Clusters: map[string]*clientcmdapi.Cluster{
			"in-cluster": {
				Server:                   cfg.Host,
				CertificateAuthorityData: cfg.CAData,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			"in-cluster": {
				Cluster:  "in-cluster",
				AuthInfo: "in-cluster",
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			"in-cluster": {
				Token: cfg.BearerToken,
			},
		},
	}
	return clientcmd.Write(kc)
}
