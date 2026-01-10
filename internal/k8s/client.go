/*
Copyright 2025 The Butler Authors.

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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	TenantClusterGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "tenantclusters",
	}

	ManagementAddonGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "managementaddons",
	}

	ProviderConfigGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "providerconfigs",
	}

	ClusterGVR = schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "clusters",
	}

	MachineDeploymentGVR = schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "machinedeployments",
	}

	TenantAddonGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "tenantaddons",
	}

	AddonDefinitionGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "addondefinitions",
	}
)

// Client wraps Kubernetes client functionality.
type Client struct {
	clientset     *kubernetes.Clientset
	dynamicClient dynamic.Interface
	config        *rest.Config
}

// NewClient creates a new Kubernetes client.
func NewClient(config *rest.Config) (*Client, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &Client{
		clientset:     clientset,
		dynamicClient: dynamicClient,
		config:        config,
	}, nil
}

// Clientset returns the core Kubernetes clientset.
func (c *Client) Clientset() *kubernetes.Clientset {
	return c.clientset
}

// Dynamic returns the dynamic client for CRD access.
func (c *Client) Dynamic() dynamic.Interface {
	return c.dynamicClient
}

// Config returns the REST config.
func (c *Client) Config() *rest.Config {
	return c.config
}

// NewClientFromKubeconfig creates a client from a kubeconfig string.
func NewClientFromKubeconfig(kubeconfig string) (*Client, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfig))
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}
	return NewClient(config)
}

// NewClientFromRESTConfig creates a new client from a REST config.
func NewClientFromRESTConfig(config *rest.Config) (*Client, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &Client{
		clientset:     clientset,
		dynamicClient: dynamicClient,
	}, nil
}

// ListTenantClusters lists all TenantCluster resources.
func (c *Client) ListTenantClusters(ctx context.Context, namespace string) (*unstructured.UnstructuredList, error) {
	if namespace == "" {
		return c.dynamicClient.Resource(TenantClusterGVR).List(ctx, metav1.ListOptions{})
	}
	return c.dynamicClient.Resource(TenantClusterGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
}

// GetTenantCluster gets a specific TenantCluster.
func (c *Client) GetTenantCluster(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	return c.dynamicClient.Resource(TenantClusterGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
}

// DeleteTenantCluster deletes a TenantCluster.
func (c *Client) DeleteTenantCluster(ctx context.Context, namespace, name string) error {
	return c.dynamicClient.Resource(TenantClusterGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

// PatchTenantCluster patches a TenantCluster.
func (c *Client) PatchTenantCluster(ctx context.Context, namespace, name string, patch []byte) (*unstructured.Unstructured, error) {
	return c.dynamicClient.Resource(TenantClusterGVR).Namespace(namespace).Patch(
		ctx, name, "application/merge-patch+json", patch, metav1.PatchOptions{},
	)
}

// ListProviderConfigs lists all ProviderConfig resources.
func (c *Client) ListProviderConfigs(ctx context.Context, namespace string) (*unstructured.UnstructuredList, error) {
	if namespace == "" {
		return c.dynamicClient.Resource(ProviderConfigGVR).List(ctx, metav1.ListOptions{})
	}
	return c.dynamicClient.Resource(ProviderConfigGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
}

// GetProviderConfig gets a specific ProviderConfig.
func (c *Client) GetProviderConfig(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	return c.dynamicClient.Resource(ProviderConfigGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
}

// GetSecret gets a Secret.
func (c *Client) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return c.clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
}

// GetClusterKubeconfig retrieves the kubeconfig for a tenant cluster.
func (c *Client) GetClusterKubeconfig(ctx context.Context, clusterNamespace, clusterName string) (string, error) {
	tc, err := c.GetTenantCluster(ctx, clusterNamespace, clusterName)
	if err != nil {
		return "", fmt.Errorf("failed to get TenantCluster: %w", err)
	}

	tenantNS, found, err := unstructured.NestedString(tc.Object, "status", "tenantNamespace")
	if err != nil || !found || tenantNS == "" {
		return "", fmt.Errorf("tenant namespace not found in TenantCluster status")
	}

	secretName := fmt.Sprintf("%s-admin-kubeconfig", clusterName)
	secret, err := c.GetSecret(ctx, tenantNS, secretName)
	if err != nil {
		return "", fmt.Errorf("failed to get kubeconfig secret: %w", err)
	}

	kubeconfig, ok := secret.Data["admin.conf"]
	if !ok {
		kubeconfig, ok = secret.Data["value"]
		if !ok {
			return "", fmt.Errorf("kubeconfig not found in secret")
		}
	}

	return string(kubeconfig), nil
}

// GetMachineDeployment gets a MachineDeployment for a cluster.
func (c *Client) GetMachineDeployment(ctx context.Context, namespace, clusterName string) (*unstructured.Unstructured, error) {
	patterns := []string{
		fmt.Sprintf("%s-workers", clusterName),
		fmt.Sprintf("%s-md-0", clusterName),
	}

	for _, name := range patterns {
		md, err := c.dynamicClient.Resource(MachineDeploymentGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			return md, nil
		}
	}

	return nil, fmt.Errorf("MachineDeployment not found for cluster %s", clusterName)
}

// GetCAPICluster gets a CAPI Cluster resource.
func (c *Client) GetCAPICluster(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	return c.dynamicClient.Resource(ClusterGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
}

// ListAddonDefinitions lists all AddonDefinition resources.
func (c *Client) ListAddonDefinitions(ctx context.Context) (*unstructured.UnstructuredList, error) {
	return c.dynamicClient.Resource(AddonDefinitionGVR).List(ctx, metav1.ListOptions{})
}

// GetAddonDefinition gets a specific AddonDefinition.
func (c *Client) GetAddonDefinition(ctx context.Context, name string) (*unstructured.Unstructured, error) {
	return c.dynamicClient.Resource(AddonDefinitionGVR).Get(ctx, name, metav1.GetOptions{})
}

// ListTenantAddons lists all TenantAddon resources for a cluster.
func (c *Client) ListTenantAddons(ctx context.Context, namespace, clusterName string) (*unstructured.UnstructuredList, error) {
	labelSelector := fmt.Sprintf("butler.butlerlabs.dev/cluster=%s", clusterName)
	return c.dynamicClient.Resource(TenantAddonGVR).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
}

// GetTenantAddon gets a specific TenantAddon.
func (c *Client) GetTenantAddon(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	return c.dynamicClient.Resource(TenantAddonGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
}

// DeleteTenantAddon deletes a TenantAddon.
func (c *Client) DeleteTenantAddon(ctx context.Context, namespace, name string) error {
	return c.dynamicClient.Resource(TenantAddonGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}
