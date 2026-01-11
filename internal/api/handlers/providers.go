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
