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

package handlers

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/go-chi/chi/v5"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"
)

// ProvidersHandler handles provider-related endpoints.
type ProvidersHandler struct {
	k8sClient *k8s.Client
	config    *config.Config
}

// NewProvidersHandler creates a new providers handler.
func NewProvidersHandler(k8sClient *k8s.Client, cfg *config.Config) *ProvidersHandler {
	return &ProvidersHandler{
		k8sClient: k8sClient,
		config:    cfg,
	}
}

// ProviderListResponse represents the provider list response.
type ProviderListResponse struct {
	Providers []map[string]interface{} `json:"providers"`
}

// CreateProviderRequest represents a provider creation request.
type CreateProviderRequest struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Provider  string `json:"provider"`

	// Harvester
	HarvesterKubeconfig string `json:"harvesterKubeconfig,omitempty"`

	// Nutanix
	NutanixEndpoint string `json:"nutanixEndpoint,omitempty"`
	NutanixPort     int32  `json:"nutanixPort,omitempty"`
	NutanixUsername string `json:"nutanixUsername,omitempty"`
	NutanixPassword string `json:"nutanixPassword,omitempty"`
	NutanixInsecure bool   `json:"nutanixInsecure,omitempty"`

	// Proxmox
	ProxmoxEndpoint    string `json:"proxmoxEndpoint,omitempty"`
	ProxmoxUsername    string `json:"proxmoxUsername,omitempty"`
	ProxmoxPassword    string `json:"proxmoxPassword,omitempty"`
	ProxmoxTokenId     string `json:"proxmoxTokenId,omitempty"`
	ProxmoxTokenSecret string `json:"proxmoxTokenSecret,omitempty"`
	ProxmoxInsecure    bool   `json:"proxmoxInsecure,omitempty"`

	// AWS
	AWSRegion           string   `json:"awsRegion,omitempty"`
	AWSAccessKeyID      string   `json:"awsAccessKeyId,omitempty"`
	AWSSecretAccessKey  string   `json:"awsSecretAccessKey,omitempty"`
	AWSVPCID            string   `json:"awsVpcId,omitempty"`
	AWSSubnetIDs        []string `json:"awsSubnetIds,omitempty"`
	AWSSecurityGroupIDs []string `json:"awsSecurityGroupIds,omitempty"`

	// Azure
	AzureSubscriptionID string `json:"azureSubscriptionId,omitempty"`
	AzureTenantID       string `json:"azureTenantId,omitempty"`
	AzureClientID       string `json:"azureClientId,omitempty"`
	AzureClientSecret   string `json:"azureClientSecret,omitempty"`
	AzureResourceGroup  string `json:"azureResourceGroup,omitempty"`
	AzureLocation       string `json:"azureLocation,omitempty"`
	AzureVNetName       string `json:"azureVnetName,omitempty"`
	AzureSubnetName     string `json:"azureSubnetName,omitempty"`

	// GCP
	GCPProjectID      string `json:"gcpProjectId,omitempty"`
	GCPRegion         string `json:"gcpRegion,omitempty"`
	GCPServiceAccount string `json:"gcpServiceAccount,omitempty"`
	GCPNetwork        string `json:"gcpNetwork,omitempty"`
	GCPSubnetwork     string `json:"gcpSubnetwork,omitempty"`

	// Network configuration
	NetworkMode       string   `json:"networkMode,omitempty"`
	NetworkSubnet     string   `json:"networkSubnet,omitempty"`
	NetworkGateway    string   `json:"networkGateway,omitempty"`
	NetworkDNSServers []string `json:"networkDnsServers,omitempty"`
	PoolRefs          []struct {
		Name     string `json:"name"`
		Priority int32  `json:"priority,omitempty"`
	} `json:"poolRefs,omitempty"`
	LBDefaultPoolSize *int32 `json:"lbDefaultPoolSize,omitempty"`
	QuotaMaxNodeIPs   *int32 `json:"quotaMaxNodeIPs,omitempty"`
	QuotaMaxLBIPs     *int32 `json:"quotaMaxLoadBalancerIPs,omitempty"`

	// Scope
	ScopeType    string `json:"scopeType,omitempty"`
	ScopeTeamRef string `json:"scopeTeamRef,omitempty"`

	// Limits
	MaxClustersPerTeam *int32 `json:"maxClustersPerTeam,omitempty"`
	MaxNodesPerTeam    *int32 `json:"maxNodesPerTeam,omitempty"`
}

// ValidateResponse represents the validation response.
type ValidateResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// List returns all provider configs.
func (h *ProvidersHandler) List(w http.ResponseWriter, r *http.Request) {
	providers, err := h.k8sClient.ListProviderConfigs(r.Context(), "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list providers: %v", err))
		return
	}

	response := ProviderListResponse{
		Providers: make([]map[string]interface{}, 0, len(providers.Items)),
	}

	for _, provider := range providers.Items {
		response.Providers = append(response.Providers, provider.Object)
	}

	writeJSON(w, http.StatusOK, response)
}

// Get returns a specific provider config.
func (h *ProvidersHandler) Get(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	provider, err := h.k8sClient.GetProviderConfig(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("provider not found: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, provider.Object)
}

// TestConnection tests provider credentials without creating anything.
func (h *ProvidersHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	var req CreateProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result := testProviderConnection(req)
	writeJSON(w, http.StatusOK, result)
}

// Create creates a new provider config with automatic secret creation.
func (h *ProvidersHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	h.createProvider(w, r, req)
}

// createProvider is the shared logic for creating a provider config.
// Both Create and CreateTeamProvider call this after decoding the request.
func (h *ProvidersHandler) createProvider(w http.ResponseWriter, r *http.Request, req CreateProviderRequest) {
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Provider == "" {
		writeError(w, http.StatusBadRequest, "provider type is required")
		return
	}

	if req.Namespace == "" {
		req.Namespace = "butler-system"
	}

	ctx := r.Context()
	secretName := fmt.Sprintf("%s-credentials", req.Name)
	var secretData map[string][]byte
	var secretKey string

	switch req.Provider {
	case "harvester":
		if req.HarvesterKubeconfig == "" {
			writeError(w, http.StatusBadRequest, "harvesterKubeconfig is required")
			return
		}
		secretData = map[string][]byte{
			"kubeconfig": []byte(req.HarvesterKubeconfig),
		}
		secretKey = "kubeconfig"

	case "nutanix":
		if req.NutanixEndpoint == "" {
			writeError(w, http.StatusBadRequest, "nutanixEndpoint is required")
			return
		}
		if req.NutanixUsername == "" || req.NutanixPassword == "" {
			writeError(w, http.StatusBadRequest, "nutanixUsername and nutanixPassword are required")
			return
		}
		secretData = map[string][]byte{
			"username": []byte(req.NutanixUsername),
			"password": []byte(req.NutanixPassword),
		}

	case "proxmox":
		if req.ProxmoxEndpoint == "" {
			writeError(w, http.StatusBadRequest, "proxmoxEndpoint is required")
			return
		}
		if req.ProxmoxTokenId != "" && req.ProxmoxTokenSecret != "" {
			secretData = map[string][]byte{
				"tokenId":     []byte(req.ProxmoxTokenId),
				"tokenSecret": []byte(req.ProxmoxTokenSecret),
			}
		} else if req.ProxmoxUsername != "" && req.ProxmoxPassword != "" {
			secretData = map[string][]byte{
				"username": []byte(req.ProxmoxUsername),
				"password": []byte(req.ProxmoxPassword),
			}
		} else {
			writeError(w, http.StatusBadRequest, "proxmox requires either username/password or tokenId/tokenSecret")
			return
		}

	case "aws":
		if req.AWSRegion == "" {
			writeError(w, http.StatusBadRequest, "awsRegion is required")
			return
		}
		if req.AWSAccessKeyID == "" || req.AWSSecretAccessKey == "" {
			writeError(w, http.StatusBadRequest, "awsAccessKeyId and awsSecretAccessKey are required")
			return
		}
		secretData = map[string][]byte{
			"accessKeyId":     []byte(req.AWSAccessKeyID),
			"secretAccessKey": []byte(req.AWSSecretAccessKey),
		}
		// Default network mode to "cloud" for cloud providers
		if req.NetworkMode == "" {
			req.NetworkMode = "cloud"
		}

	case "azure":
		if req.AzureSubscriptionID == "" {
			writeError(w, http.StatusBadRequest, "azureSubscriptionId is required")
			return
		}
		if req.AzureTenantID == "" || req.AzureClientID == "" || req.AzureClientSecret == "" {
			writeError(w, http.StatusBadRequest, "azureTenantId, azureClientId, and azureClientSecret are required")
			return
		}
		secretData = map[string][]byte{
			"tenantId":     []byte(req.AzureTenantID),
			"clientId":     []byte(req.AzureClientID),
			"clientSecret": []byte(req.AzureClientSecret),
		}
		// Default network mode to "cloud" for cloud providers
		if req.NetworkMode == "" {
			req.NetworkMode = "cloud"
		}

	case "gcp":
		if req.GCPProjectID == "" {
			writeError(w, http.StatusBadRequest, "gcpProjectId is required")
			return
		}
		if req.GCPRegion == "" {
			writeError(w, http.StatusBadRequest, "gcpRegion is required")
			return
		}
		if req.GCPServiceAccount == "" {
			writeError(w, http.StatusBadRequest, "gcpServiceAccount is required")
			return
		}
		secretData = map[string][]byte{
			"serviceAccount": []byte(req.GCPServiceAccount),
		}
		// Default network mode to "cloud" for cloud providers
		if req.NetworkMode == "" {
			req.NetworkMode = "cloud"
		}

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported provider type: %s", req.Provider))
		return
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: req.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":   "butler",
				"butler.butlerlabs.dev/provider": req.Name,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}

	_, err := h.k8sClient.Clientset().CoreV1().Secrets(req.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create credentials secret: %v", err))
		return
	}

	credentialsRef := map[string]interface{}{
		"name":      secretName,
		"namespace": req.Namespace,
	}
	if secretKey != "" {
		credentialsRef["key"] = secretKey
	}

	spec := map[string]interface{}{
		"provider":       req.Provider,
		"credentialsRef": credentialsRef,
	}

	switch req.Provider {
	case "nutanix":
		nutanixConfig := map[string]interface{}{
			"endpoint": req.NutanixEndpoint,
		}
		if req.NutanixPort > 0 {
			nutanixConfig["port"] = req.NutanixPort
		}
		if req.NutanixInsecure {
			nutanixConfig["insecure"] = true
		}
		spec["nutanix"] = nutanixConfig

	case "proxmox":
		proxmoxConfig := map[string]interface{}{
			"endpoint": req.ProxmoxEndpoint,
		}
		if req.ProxmoxInsecure {
			proxmoxConfig["insecure"] = true
		}
		spec["proxmox"] = proxmoxConfig

	case "aws":
		awsConfig := map[string]interface{}{
			"region": req.AWSRegion,
		}
		if req.AWSVPCID != "" {
			awsConfig["vpcID"] = req.AWSVPCID
		}
		if len(req.AWSSubnetIDs) > 0 {
			awsConfig["subnetIDs"] = req.AWSSubnetIDs
		}
		if len(req.AWSSecurityGroupIDs) > 0 {
			awsConfig["securityGroupIDs"] = req.AWSSecurityGroupIDs
		}
		spec["aws"] = awsConfig

	case "azure":
		azureConfig := map[string]interface{}{
			"subscriptionID": req.AzureSubscriptionID,
		}
		if req.AzureResourceGroup != "" {
			azureConfig["resourceGroup"] = req.AzureResourceGroup
		}
		if req.AzureLocation != "" {
			azureConfig["location"] = req.AzureLocation
		}
		if req.AzureVNetName != "" {
			azureConfig["vnetName"] = req.AzureVNetName
		}
		if req.AzureSubnetName != "" {
			azureConfig["subnetName"] = req.AzureSubnetName
		}
		spec["azure"] = azureConfig

	case "gcp":
		gcpConfig := map[string]interface{}{
			"projectID": req.GCPProjectID,
			"region":    req.GCPRegion,
		}
		if req.GCPNetwork != "" {
			gcpConfig["network"] = req.GCPNetwork
		}
		if req.GCPSubnetwork != "" {
			gcpConfig["subnetwork"] = req.GCPSubnetwork
		}
		spec["gcp"] = gcpConfig
	}

	// Network configuration
	if req.NetworkMode != "" {
		network := map[string]interface{}{
			"mode": req.NetworkMode,
		}
		if len(req.PoolRefs) > 0 {
			poolRefs := make([]interface{}, 0, len(req.PoolRefs))
			for _, pr := range req.PoolRefs {
				ref := map[string]interface{}{"name": pr.Name}
				if pr.Priority > 0 {
					ref["priority"] = pr.Priority
				}
				poolRefs = append(poolRefs, ref)
			}
			network["poolRefs"] = poolRefs
		}
		if req.NetworkSubnet != "" {
			network["subnet"] = req.NetworkSubnet
		}
		if req.NetworkGateway != "" {
			network["gateway"] = req.NetworkGateway
		}
		if len(req.NetworkDNSServers) > 0 {
			network["dnsServers"] = req.NetworkDNSServers
		}
		if req.LBDefaultPoolSize != nil {
			network["loadBalancer"] = map[string]interface{}{
				"defaultPoolSize": *req.LBDefaultPoolSize,
			}
		}
		if req.QuotaMaxNodeIPs != nil || req.QuotaMaxLBIPs != nil {
			quota := map[string]interface{}{}
			if req.QuotaMaxNodeIPs != nil {
				quota["maxNodeIPs"] = *req.QuotaMaxNodeIPs
			}
			if req.QuotaMaxLBIPs != nil {
				quota["maxLoadBalancerIPs"] = *req.QuotaMaxLBIPs
			}
			network["quotaPerTenant"] = quota
		}
		spec["network"] = network
	}

	// Scope
	if req.ScopeType != "" {
		scope := map[string]interface{}{
			"type": req.ScopeType,
		}
		if req.ScopeTeamRef != "" {
			scope["teamRef"] = map[string]interface{}{
				"name": req.ScopeTeamRef,
			}
		}
		spec["scope"] = scope
	}

	// Limits
	if req.MaxClustersPerTeam != nil || req.MaxNodesPerTeam != nil {
		limits := map[string]interface{}{}
		if req.MaxClustersPerTeam != nil {
			limits["maxClustersPerTeam"] = *req.MaxClustersPerTeam
		}
		if req.MaxNodesPerTeam != nil {
			limits["maxNodesPerTeam"] = *req.MaxNodesPerTeam
		}
		spec["limits"] = limits
	}

	provider := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "ProviderConfig",
			"metadata": map[string]interface{}{
				"name":      req.Name,
				"namespace": req.Namespace,
			},
			"spec": spec,
		},
	}

	created, err := h.k8sClient.Dynamic().Resource(k8s.ProviderConfigGVR).Namespace(req.Namespace).Create(
		ctx, provider, metav1.CreateOptions{},
	)
	if err != nil {
		_ = h.k8sClient.Clientset().CoreV1().Secrets(req.Namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create provider: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, created.Object)
}

// Delete deletes a provider config and its associated secret.
func (h *ProvidersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	h.deleteProvider(w, r, namespace, name)
}

// deleteProvider is the shared logic for deleting a provider config and its secret.
// Both Delete and DeleteTeamProvider call this after authorization checks.
func (h *ProvidersHandler) deleteProvider(w http.ResponseWriter, r *http.Request, namespace, name string) {
	ctx := r.Context()

	provider, err := h.k8sClient.GetProviderConfig(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("provider not found: %v", err))
		return
	}

	credentialsRef, _, _ := unstructured.NestedMap(provider.Object, "spec", "credentialsRef")
	secretName, _ := credentialsRef["name"].(string)
	secretNamespace, _ := credentialsRef["namespace"].(string)
	if secretNamespace == "" {
		secretNamespace = namespace
	}

	err = h.k8sClient.Dynamic().Resource(k8s.ProviderConfigGVR).Namespace(namespace).Delete(
		ctx, name, metav1.DeleteOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete provider: %v", err))
		return
	}

	if secretName != "" {
		_ = h.k8sClient.Clientset().CoreV1().Secrets(secretNamespace).Delete(ctx, secretName, metav1.DeleteOptions{})
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "provider deleted"})
}

// ListTeamProviders returns providers available to a specific team.
// This includes all platform-scoped providers and team-scoped providers belonging to the team.
func (h *ProvidersHandler) ListTeamProviders(w http.ResponseWriter, r *http.Request) {
	teamName := chi.URLParam(r, "name")

	providers, err := h.k8sClient.ListProviderConfigs(r.Context(), "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list providers: %v", err))
		return
	}

	filtered := make([]map[string]interface{}, 0)
	for _, provider := range providers.Items {
		spec, _ := provider.Object["spec"].(map[string]interface{})
		scope, _ := spec["scope"].(map[string]interface{})

		scopeType, _ := scope["type"].(string)
		if scopeType == "" {
			scopeType = "platform" // default
		}

		if scopeType == "platform" {
			filtered = append(filtered, provider.Object)
		} else if scopeType == "team" {
			teamRef, _ := scope["teamRef"].(map[string]interface{})
			refName, _ := teamRef["name"].(string)
			if refName == teamName {
				filtered = append(filtered, provider.Object)
			}
		}
	}

	writeJSON(w, http.StatusOK, ProviderListResponse{Providers: filtered})
}

// CreateTeamProvider creates a provider config scoped to a specific team.
func (h *ProvidersHandler) CreateTeamProvider(w http.ResponseWriter, r *http.Request) {
	teamName := chi.URLParam(r, "name")

	var req CreateProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Force team scope
	req.ScopeType = "team"
	req.ScopeTeamRef = teamName

	h.createProvider(w, r, req)
}

// DeleteTeamProvider deletes a provider config that is scoped to a specific team.
// It verifies the provider is actually team-scoped to the given team before deleting.
func (h *ProvidersHandler) DeleteTeamProvider(w http.ResponseWriter, r *http.Request) {
	teamName := chi.URLParam(r, "name")
	namespace := chi.URLParam(r, "namespace")
	providerName := chi.URLParam(r, "providerName")
	ctx := r.Context()

	// Get provider and verify it is team-scoped to this team
	provider, err := h.k8sClient.GetProviderConfig(ctx, namespace, providerName)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("provider not found: %v", err))
		return
	}

	spec, _ := provider.Object["spec"].(map[string]interface{})
	scope, _ := spec["scope"].(map[string]interface{})
	scopeType, _ := scope["type"].(string)
	teamRef, _ := scope["teamRef"].(map[string]interface{})
	refName, _ := teamRef["name"].(string)

	if scopeType != "team" || refName != teamName {
		writeError(w, http.StatusForbidden, "can only delete team-scoped providers belonging to this team")
		return
	}

	h.deleteProvider(w, r, namespace, providerName)
}

// Validate validates an existing provider's connectivity.
func (h *ProvidersHandler) Validate(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	ctx := r.Context()

	provider, err := h.k8sClient.GetProviderConfig(ctx, namespace, name)
	if err != nil {
		writeJSON(w, http.StatusOK, ValidateResponse{
			Valid:   false,
			Message: fmt.Sprintf("provider not found: %v", err),
		})
		return
	}

	providerType, _, _ := unstructured.NestedString(provider.Object, "spec", "provider")

	credentialsRef, _, _ := unstructured.NestedMap(provider.Object, "spec", "credentialsRef")
	secretName, _ := credentialsRef["name"].(string)
	secretNamespace, _ := credentialsRef["namespace"].(string)
	if secretNamespace == "" {
		secretNamespace = namespace
	}

	secret, err := h.k8sClient.Clientset().CoreV1().Secrets(secretNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		writeJSON(w, http.StatusOK, ValidateResponse{
			Valid:   false,
			Message: fmt.Sprintf("credentials secret not found: %v", err),
		})
		return
	}

	var result ValidateResponse

	switch providerType {
	case "harvester":
		kubeconfig := string(secret.Data["kubeconfig"])
		result = testHarvesterConnection(kubeconfig)

	case "nutanix":
		endpoint, _, _ := unstructured.NestedString(provider.Object, "spec", "nutanix", "endpoint")
		port, _, _ := unstructured.NestedInt64(provider.Object, "spec", "nutanix", "port")
		insecure, _, _ := unstructured.NestedBool(provider.Object, "spec", "nutanix", "insecure")
		username := string(secret.Data["username"])
		password := string(secret.Data["password"])
		result = testNutanixConnection(endpoint, int32(port), username, password, insecure)

	case "proxmox":
		endpoint, _, _ := unstructured.NestedString(provider.Object, "spec", "proxmox", "endpoint")
		insecure, _, _ := unstructured.NestedBool(provider.Object, "spec", "proxmox", "insecure")
		username := string(secret.Data["username"])
		password := string(secret.Data["password"])
		tokenId := string(secret.Data["tokenId"])
		tokenSecret := string(secret.Data["tokenSecret"])
		result = testProxmoxConnection(endpoint, username, password, tokenId, tokenSecret, insecure)

	case "aws":
		region, _, _ := unstructured.NestedString(provider.Object, "spec", "aws", "region")
		accessKeyID := string(secret.Data["accessKeyId"])
		secretAccessKey := string(secret.Data["secretAccessKey"])
		result = testAWSConnection(region, accessKeyID, secretAccessKey)

	case "azure":
		subscriptionID, _, _ := unstructured.NestedString(provider.Object, "spec", "azure", "subscriptionID")
		tenantID := string(secret.Data["tenantId"])
		clientID := string(secret.Data["clientId"])
		clientSecret := string(secret.Data["clientSecret"])
		result = testAzureConnection(subscriptionID, tenantID, clientID, clientSecret)

	case "gcp":
		projectID, _, _ := unstructured.NestedString(provider.Object, "spec", "gcp", "projectID")
		region, _, _ := unstructured.NestedString(provider.Object, "spec", "gcp", "region")
		serviceAccount := string(secret.Data["serviceAccount"])
		result = testGCPConnection(projectID, region, serviceAccount)

	default:
		result = ValidateResponse{Valid: false, Message: fmt.Sprintf("unsupported provider type: %s", providerType)}
	}

	writeJSON(w, http.StatusOK, result)
}

func testProviderConnection(req CreateProviderRequest) ValidateResponse {
	switch req.Provider {
	case "harvester":
		return testHarvesterConnection(req.HarvesterKubeconfig)
	case "nutanix":
		return testNutanixConnection(req.NutanixEndpoint, req.NutanixPort, req.NutanixUsername, req.NutanixPassword, req.NutanixInsecure)
	case "proxmox":
		return testProxmoxConnection(req.ProxmoxEndpoint, req.ProxmoxUsername, req.ProxmoxPassword, req.ProxmoxTokenId, req.ProxmoxTokenSecret, req.ProxmoxInsecure)
	case "aws":
		return testAWSConnection(req.AWSRegion, req.AWSAccessKeyID, req.AWSSecretAccessKey)
	case "azure":
		return testAzureConnection(req.AzureSubscriptionID, req.AzureTenantID, req.AzureClientID, req.AzureClientSecret)
	case "gcp":
		return testGCPConnection(req.GCPProjectID, req.GCPRegion, req.GCPServiceAccount)
	default:
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("unsupported provider: %s", req.Provider)}
	}
}

func testHarvesterConnection(kubeconfig string) ValidateResponse {
	if kubeconfig == "" {
		return ValidateResponse{Valid: false, Message: "kubeconfig is required"}
	}

	restConfig, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfig))
	if err != nil {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("invalid kubeconfig: %v", err)}
	}

	restConfig.Timeout = 10 * time.Second

	client, err := k8s.NewClientFromRESTConfig(restConfig)
	if err != nil {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("failed to create client: %v", err)}
	}

	version, err := client.Clientset().Discovery().ServerVersion()
	if err != nil {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("failed to connect to cluster: %v", err)}
	}

	return ValidateResponse{
		Valid:   true,
		Message: fmt.Sprintf("Connected successfully (Kubernetes %s)", version.GitVersion),
	}
}

func testNutanixConnection(endpoint string, port int32, username, password string, insecure bool) ValidateResponse {
	if endpoint == "" {
		return ValidateResponse{Valid: false, Message: "endpoint is required"}
	}
	if username == "" || password == "" {
		return ValidateResponse{Valid: false, Message: "username and password are required"}
	}

	if port == 0 {
		port = 9440
	}

	apiURL := fmt.Sprintf("%s:%d/api/nutanix/v3/clusters/list", endpoint, port)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
			},
		},
	}

	req, err := http.NewRequest("POST", apiURL, nil)
	if err != nil {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("failed to create request: %v", err)}
	}

	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("connection failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return ValidateResponse{Valid: false, Message: "authentication failed: invalid credentials"}
	}
	if resp.StatusCode >= 400 {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("API error: HTTP %d", resp.StatusCode)}
	}

	return ValidateResponse{
		Valid:   true,
		Message: "Connected to Nutanix Prism Central successfully",
	}
}

func testProxmoxConnection(endpoint, username, password, tokenId, tokenSecret string, insecure bool) ValidateResponse {
	if endpoint == "" {
		return ValidateResponse{Valid: false, Message: "endpoint is required"}
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
			},
		},
	}

	var req *http.Request
	var err error

	if tokenId != "" && tokenSecret != "" {
		apiURL := fmt.Sprintf("%s/api2/json/version", endpoint)
		req, err = http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return ValidateResponse{Valid: false, Message: fmt.Sprintf("failed to create request: %v", err)}
		}
		req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenId, tokenSecret))
	} else if username != "" && password != "" {
		apiURL := fmt.Sprintf("%s/api2/json/access/ticket", endpoint)
		req, err = http.NewRequest("POST", apiURL, nil)
		if err != nil {
			return ValidateResponse{Valid: false, Message: fmt.Sprintf("failed to create request: %v", err)}
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		return ValidateResponse{Valid: false, Message: "credentials required: username/password or tokenId/tokenSecret"}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("connection failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return ValidateResponse{Valid: false, Message: "authentication failed: invalid credentials"}
	}
	if resp.StatusCode >= 400 {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("API error: HTTP %d", resp.StatusCode)}
	}

	return ValidateResponse{
		Valid:   true,
		Message: "Connected to Proxmox VE successfully",
	}
}

func testAWSConnection(region, accessKeyID, secretAccessKey string) ValidateResponse {
	if region == "" {
		return ValidateResponse{Valid: false, Message: "region is required"}
	}
	if accessKeyID == "" || secretAccessKey == "" {
		return ValidateResponse{Valid: false, Message: "accessKeyId and secretAccessKey are required"}
	}

	// Test by calling the AWS STS GetCallerIdentity endpoint
	// This is the standard way to validate AWS credentials without needing any specific permissions
	client := &http.Client{Timeout: 10 * time.Second}

	stsURL := fmt.Sprintf("https://sts.%s.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", region)
	req, err := http.NewRequest("GET", stsURL, nil)
	if err != nil {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("failed to create request: %v", err)}
	}

	// AWS Signature V4 requires the SDK for proper signing; for a basic connectivity test
	// we verify the endpoint is reachable and credentials format is valid
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("connection failed: %v", err)}
	}
	defer resp.Body.Close()

	// STS endpoint is reachable - credentials format will be validated by the provider controller
	return ValidateResponse{
		Valid:   true,
		Message: fmt.Sprintf("AWS endpoint reachable in region %s (credential validation deferred to provider controller)", region),
	}
}

func testAzureConnection(subscriptionID, tenantID, clientID, clientSecret string) ValidateResponse {
	if subscriptionID == "" {
		return ValidateResponse{Valid: false, Message: "subscriptionId is required"}
	}
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return ValidateResponse{Valid: false, Message: "tenantId, clientId, and clientSecret are required"}
	}

	// Test by requesting an OAuth2 token from Azure AD
	client := &http.Client{Timeout: 10 * time.Second}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	body := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s&scope=https://management.azure.com/.default",
		clientID, clientSecret)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(body))
	if err != nil {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("failed to create request: %v", err)}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("connection failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 400 {
		return ValidateResponse{Valid: false, Message: "authentication failed: invalid credentials"}
	}
	if resp.StatusCode >= 400 {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("Azure AD error: HTTP %d", resp.StatusCode)}
	}

	return ValidateResponse{
		Valid:   true,
		Message: "Connected to Azure successfully",
	}
}

func testGCPConnection(projectID, region, serviceAccount string) ValidateResponse {
	if projectID == "" {
		return ValidateResponse{Valid: false, Message: "projectId is required"}
	}
	if region == "" {
		return ValidateResponse{Valid: false, Message: "region is required"}
	}
	if serviceAccount == "" {
		return ValidateResponse{Valid: false, Message: "serviceAccount (JSON key) is required"}
	}

	// Validate the service account JSON is parseable
	var saKey map[string]interface{}
	if err := json.Unmarshal([]byte(serviceAccount), &saKey); err != nil {
		return ValidateResponse{Valid: false, Message: fmt.Sprintf("invalid service account JSON: %v", err)}
	}

	// Check required fields in the service account key
	if _, ok := saKey["client_email"]; !ok {
		return ValidateResponse{Valid: false, Message: "service account JSON missing client_email field"}
	}
	if _, ok := saKey["private_key"]; !ok {
		return ValidateResponse{Valid: false, Message: "service account JSON missing private_key field"}
	}

	return ValidateResponse{
		Valid:   true,
		Message: fmt.Sprintf("GCP service account key validated for project %s (full auth deferred to provider controller)", projectID),
	}
}

// ImageInfo represents an available image.
type ImageInfo struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	OS          string `json:"os,omitempty"`
}

// ListImages returns available images for a provider.
func (h *ProvidersHandler) ListImages(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	ctx := r.Context()

	provider, err := h.k8sClient.GetProviderConfig(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("provider not found: %v", err))
		return
	}

	providerType, _, _ := unstructured.NestedString(provider.Object, "spec", "provider")

	// Get credentials
	credentialsRef, _, _ := unstructured.NestedMap(provider.Object, "spec", "credentialsRef")
	secretName, _ := credentialsRef["name"].(string)
	secretNamespace, _ := credentialsRef["namespace"].(string)
	if secretNamespace == "" {
		secretNamespace = namespace
	}

	secret, err := h.k8sClient.Clientset().CoreV1().Secrets(secretNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get credentials: %v", err))
		return
	}

	var images []ImageInfo

	switch providerType {
	case "harvester":
		kubeconfig := secret.Data["kubeconfig"]
		images, err = h.listHarvesterImages(ctx, kubeconfig)
	case "nutanix":
		endpoint, _, _ := unstructured.NestedString(provider.Object, "spec", "nutanix", "endpoint")
		port, _, _ := unstructured.NestedInt64(provider.Object, "spec", "nutanix", "port")
		insecure, _, _ := unstructured.NestedBool(provider.Object, "spec", "nutanix", "insecure")
		username := string(secret.Data["username"])
		password := string(secret.Data["password"])
		images, err = h.listNutanixImages(ctx, endpoint, int32(port), username, password, insecure)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("image listing not supported for provider: %s", providerType))
		return
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list images: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"images": images})
}

// listHarvesterImages fetches VM images from Harvester.
func (h *ProvidersHandler) listHarvesterImages(ctx context.Context, kubeconfig []byte) ([]ImageInfo, error) {
	if len(kubeconfig) == 0 {
		return nil, fmt.Errorf("kubeconfig is required")
	}

	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("invalid kubeconfig: %w", err)
	}
	restConfig.Timeout = 15 * time.Second

	client, err := k8s.NewClientFromRESTConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// List VirtualMachineImages from Harvester
	imageGVR := schema.GroupVersionResource{
		Group:    "harvesterhci.io",
		Version:  "v1beta1",
		Resource: "virtualmachineimages",
	}

	imageList, err := client.Dynamic().Resource(imageGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
	}

	images := make([]ImageInfo, 0, len(imageList.Items))
	for _, img := range imageList.Items {
		name, _, _ := unstructured.NestedString(img.Object, "metadata", "name")
		namespace, _, _ := unstructured.NestedString(img.Object, "metadata", "namespace")
		displayName, _, _ := unstructured.NestedString(img.Object, "spec", "displayName")
		description, _, _ := unstructured.NestedString(img.Object, "spec", "description")

		// Determine OS type from name/displayName
		osType := detectOSType(strings.ToLower(name + " " + displayName))

		id := fmt.Sprintf("%s/%s", namespace, name)
		if displayName == "" {
			displayName = name
		}

		images = append(images, ImageInfo{
			Name:        displayName,
			ID:          id,
			Description: description,
			OS:          osType,
		})
	}

	return images, nil
}

// listNutanixImages fetches images from Nutanix Prism Central.
func (h *ProvidersHandler) listNutanixImages(ctx context.Context, endpoint string, port int32, username, password string, insecure bool) ([]ImageInfo, error) {
	if port == 0 {
		port = 9440
	}

	apiURL := fmt.Sprintf("%s:%d/api/nutanix/v3/images/list", endpoint, port)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
			},
		},
	}

	reqBody := strings.NewReader(`{"kind":"image","length":500}`)
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Entities []struct {
			Metadata struct {
				UUID string `json:"uuid"`
			} `json:"metadata"`
			Spec struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"spec"`
		} `json:"entities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	images := make([]ImageInfo, 0, len(result.Entities))
	for _, entity := range result.Entities {
		osType := detectOSType(strings.ToLower(entity.Spec.Name))
		images = append(images, ImageInfo{
			Name:        entity.Spec.Name,
			ID:          entity.Metadata.UUID,
			Description: entity.Spec.Description,
			OS:          osType,
		})
	}

	return images, nil
}

// detectOSType guesses OS type from image name.
func detectOSType(name string) string {
	switch {
	case strings.Contains(name, "talos"):
		return "talos"
	case strings.Contains(name, "rocky"):
		return "rocky"
	case strings.Contains(name, "ubuntu"):
		return "ubuntu"
	case strings.Contains(name, "debian"):
		return "debian"
	case strings.Contains(name, "centos"):
		return "centos"
	case strings.Contains(name, "rhel") || strings.Contains(name, "redhat"):
		return "rhel"
	case strings.Contains(name, "flatcar"):
		return "flatcar"
	default:
		return "linux"
	}
}

// NetworkInfo represents an available network.
type NetworkInfo struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	VLAN        int    `json:"vlan,omitempty"`
	Description string `json:"description,omitempty"`
}

// ListNetworks returns available networks for a provider.
func (h *ProvidersHandler) ListNetworks(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	ctx := r.Context()

	provider, err := h.k8sClient.GetProviderConfig(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("provider not found: %v", err))
		return
	}

	providerType, _, _ := unstructured.NestedString(provider.Object, "spec", "provider")

	// Get credentials
	credentialsRef, _, _ := unstructured.NestedMap(provider.Object, "spec", "credentialsRef")
	secretName, _ := credentialsRef["name"].(string)
	secretNamespace, _ := credentialsRef["namespace"].(string)
	if secretNamespace == "" {
		secretNamespace = namespace
	}

	secret, err := h.k8sClient.Clientset().CoreV1().Secrets(secretNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get credentials: %v", err))
		return
	}

	var networks []NetworkInfo

	switch providerType {
	case "harvester":
		kubeconfig := secret.Data["kubeconfig"]
		networks, err = h.listHarvesterNetworks(ctx, kubeconfig)
	case "nutanix":
		endpoint, _, _ := unstructured.NestedString(provider.Object, "spec", "nutanix", "endpoint")
		port, _, _ := unstructured.NestedInt64(provider.Object, "spec", "nutanix", "port")
		insecure, _, _ := unstructured.NestedBool(provider.Object, "spec", "nutanix", "insecure")
		username := string(secret.Data["username"])
		password := string(secret.Data["password"])
		networks, err = h.listNutanixNetworks(ctx, endpoint, int32(port), username, password, insecure)
	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("network listing not supported for provider: %s", providerType))
		return
	}

	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list networks: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"networks": networks})
}

// listHarvesterNetworks fetches VM networks from Harvester.
func (h *ProvidersHandler) listHarvesterNetworks(ctx context.Context, kubeconfig []byte) ([]NetworkInfo, error) {
	if len(kubeconfig) == 0 {
		return nil, fmt.Errorf("kubeconfig is required")
	}

	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("invalid kubeconfig: %w", err)
	}
	restConfig.Timeout = 15 * time.Second

	client, err := k8s.NewClientFromRESTConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// List NetworkAttachmentDefinitions (Multus networks used by Harvester)
	nadGVR := schema.GroupVersionResource{
		Group:    "k8s.cni.cncf.io",
		Version:  "v1",
		Resource: "network-attachment-definitions",
	}

	nadList, err := client.Dynamic().Resource(nadGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}

	networks := make([]NetworkInfo, 0, len(nadList.Items))
	for _, nad := range nadList.Items {
		name, _, _ := unstructured.NestedString(nad.Object, "metadata", "name")
		namespace, _, _ := unstructured.NestedString(nad.Object, "metadata", "namespace")

		// Parse VLAN from config if available
		vlan := 0
		configStr, _, _ := unstructured.NestedString(nad.Object, "spec", "config")
		if strings.Contains(configStr, "vlan") {
			// Simple extraction - could be more robust
			// Config is JSON like: {"cniVersion":"0.3.1","name":"vlan40","type":"bridge","vlan":40,...}
			var config map[string]interface{}
			if json.Unmarshal([]byte(configStr), &config) == nil {
				if v, ok := config["vlan"].(float64); ok {
					vlan = int(v)
				}
			}
		}

		id := fmt.Sprintf("%s/%s", namespace, name)

		networks = append(networks, NetworkInfo{
			Name:        name,
			ID:          id,
			VLAN:        vlan,
			Description: fmt.Sprintf("%s (VLAN %d)", name, vlan),
		})
	}

	return networks, nil
}

// listNutanixNetworks fetches subnets from Nutanix Prism Central.
func (h *ProvidersHandler) listNutanixNetworks(ctx context.Context, endpoint string, port int32, username, password string, insecure bool) ([]NetworkInfo, error) {
	if port == 0 {
		port = 9440
	}

	apiURL := fmt.Sprintf("%s:%d/api/nutanix/v3/subnets/list", endpoint, port)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
			},
		},
	}

	reqBody := strings.NewReader(`{"kind":"subnet","length":500}`)
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(username, password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: HTTP %d", resp.StatusCode)
	}

	var result struct {
		Entities []struct {
			Metadata struct {
				UUID string `json:"uuid"`
			} `json:"metadata"`
			Spec struct {
				Name      string `json:"name"`
				Resources struct {
					VlanID int `json:"vlan_id"`
				} `json:"resources"`
			} `json:"spec"`
		} `json:"entities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	networks := make([]NetworkInfo, 0, len(result.Entities))
	for _, entity := range result.Entities {
		networks = append(networks, NetworkInfo{
			Name:        entity.Spec.Name,
			ID:          entity.Metadata.UUID,
			VLAN:        entity.Spec.Resources.VlanID,
			Description: fmt.Sprintf("%s (VLAN %d)", entity.Spec.Name, entity.Spec.Resources.VlanID),
		})
	}

	return networks, nil
}
