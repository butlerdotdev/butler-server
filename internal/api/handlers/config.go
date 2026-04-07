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

package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	butlerv1alpha1 "github.com/butlerdotdev/butler-api/api/v1alpha1"
	"github.com/butlerdotdev/butler-server/internal/audit"
	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"
	"k8s.io/apimachinery/pkg/api/resource"
)

// ConfigHandler handles ButlerConfig management API requests.
type ConfigHandler struct {
	k8sClient    *k8s.Client
	config       *config.Config
	logger       *slog.Logger
	auditEmitter *audit.Emitter
}

// NewConfigHandler creates a new config handler.
func NewConfigHandler(k8sClient *k8s.Client, cfg *config.Config, logger *slog.Logger, auditEmitter *audit.Emitter) *ConfigHandler {
	return &ConfigHandler{
		k8sClient:    k8sClient,
		config:       cfg,
		logger:       logger,
		auditEmitter: auditEmitter,
	}
}

// --- Request/Response Types ---

// ButlerConfigResponse is the API response for platform configuration.
type ButlerConfigResponse struct {
	// General settings
	MultiTenancy         *MultiTenancyInfo         `json:"multiTenancy"`
	DefaultNamespace     string                    `json:"defaultNamespace"`
	DefaultProviderRef   *ProviderRefInfo          `json:"defaultProviderRef,omitempty"`
	ControlPlaneExposure *ControlPlaneExposureInfo `json:"controlPlaneExposure,omitempty"`

	// Defaults
	DefaultAddonVersions        *AddonVersionsInfo        `json:"defaultAddonVersions,omitempty"`
	DefaultTeamLimits           *TeamLimitsInfo            `json:"defaultTeamLimits,omitempty"`
	DefaultControlPlaneResources *CPResourcesInfo          `json:"defaultControlPlaneResources,omitempty"`

	// Integrations
	ImageFactory     *ImageFactoryInfo `json:"imageFactory,omitempty"`
	Audit            *AuditInfo        `json:"audit,omitempty"`
	SSHAuthorizedKey string            `json:"sshAuthorizedKey,omitempty"`

	// Read-only status
	Status *ConfigStatusInfo `json:"status"`
}

// MultiTenancyInfo contains multi-tenancy configuration.
type MultiTenancyInfo struct {
	Mode string `json:"mode"`
}

// ProviderRefInfo contains the default provider reference.
type ProviderRefInfo struct {
	Name string `json:"name"`
}

// ControlPlaneExposureInfo contains control plane exposure settings.
type ControlPlaneExposureInfo struct {
	Mode             string `json:"mode"`
	Hostname         string `json:"hostname"`
	IngressClassName string `json:"ingressClassName"`
	ControllerType   string `json:"controllerType"`
	GatewayRef       string `json:"gatewayRef"`
}

// AddonVersionsInfo contains default addon versions.
type AddonVersionsInfo struct {
	Cilium      string `json:"cilium,omitempty"`
	MetalLB     string `json:"metallb,omitempty"`
	CertManager string `json:"certManager,omitempty"`
	Longhorn    string `json:"longhorn,omitempty"`
	Traefik     string `json:"traefik,omitempty"`
	FluxCD      string `json:"fluxcd,omitempty"`
}

// TeamLimitsInfo contains default team resource limits.
type TeamLimitsInfo struct {
	MaxClusters          *int32 `json:"maxClusters,omitempty"`
	MaxWorkersPerCluster *int32 `json:"maxWorkersPerCluster,omitempty"`
	MaxTotalCPU          string `json:"maxTotalCPU,omitempty"`
	MaxTotalMemory       string `json:"maxTotalMemory,omitempty"`
	MaxTotalStorage      string `json:"maxTotalStorage,omitempty"`
}

// CPResourcesInfo contains default control plane resource allocations.
type CPResourcesInfo struct {
	APIServer         *ComponentResourcesInfo `json:"apiServer,omitempty"`
	ControllerManager *ComponentResourcesInfo `json:"controllerManager,omitempty"`
	Scheduler         *ComponentResourcesInfo `json:"scheduler,omitempty"`
}

// ComponentResourcesInfo contains requests/limits for a single component.
type ComponentResourcesInfo struct {
	Requests *ResourceQuantitiesInfo `json:"requests,omitempty"`
	Limits   *ResourceQuantitiesInfo `json:"limits,omitempty"`
}

// ResourceQuantitiesInfo contains CPU and memory as strings.
type ResourceQuantitiesInfo struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// ImageFactoryInfo contains image factory configuration.
type ImageFactoryInfo struct {
	URL                string `json:"url"`
	CredentialsRef     string `json:"credentialsRef"`
	DefaultSchematicID string `json:"defaultSchematicID"`
	AutoSync           *bool  `json:"autoSync,omitempty"`
}

// AuditInfo contains audit log configuration.
type AuditInfo struct {
	Enabled    *bool  `json:"enabled,omitempty"`
	WebhookURL string `json:"webhookURL,omitempty"`
	BufferSize *int32 `json:"bufferSize,omitempty"`
}

// ConfigStatusInfo contains read-only platform status.
type ConfigStatusInfo struct {
	TeamCount                int32  `json:"teamCount"`
	ClusterCount             int32  `json:"clusterCount"`
	ControlPlaneExposureMode string `json:"controlPlaneExposureMode,omitempty"`
	TCPProxyRequired         bool   `json:"tcpProxyRequired"`
}

// UpdateConfigRequest is the request body for updating ButlerConfig.
type UpdateConfigRequest struct {
	MultiTenancy                *MultiTenancyInfo         `json:"multiTenancy,omitempty"`
	DefaultNamespace            *string                   `json:"defaultNamespace,omitempty"`
	DefaultProviderRef          *ProviderRefInfo          `json:"defaultProviderRef,omitempty"`
	ControlPlaneExposure        *ControlPlaneExposureInfo `json:"controlPlaneExposure,omitempty"`
	DefaultAddonVersions        *AddonVersionsInfo        `json:"defaultAddonVersions,omitempty"`
	DefaultTeamLimits           *TeamLimitsInfo            `json:"defaultTeamLimits,omitempty"`
	DefaultControlPlaneResources *CPResourcesInfo          `json:"defaultControlPlaneResources,omitempty"`
	ImageFactory                *ImageFactoryInfo          `json:"imageFactory,omitempty"`
	Audit                       *AuditInfo                 `json:"audit,omitempty"`
	SSHAuthorizedKey            *string                    `json:"sshAuthorizedKey,omitempty"`
}

// --- Handlers ---

// GetConfig returns the current ButlerConfig platform configuration. Admin only.
func (h *ConfigHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	bc, err := h.k8sClient.GetButlerConfigTyped(ctx)
	if err != nil {
		h.logger.Error("Failed to get ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get platform configuration")
		return
	}

	resp := h.buildResponse(bc)
	writeJSON(w, http.StatusOK, resp)
}

// UpdateConfig updates the ButlerConfig platform configuration. Admin only.
func (h *ConfigHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req UpdateConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	bc, err := h.k8sClient.GetButlerConfigTyped(ctx)
	if err != nil {
		h.logger.Error("Failed to get ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get platform configuration")
		return
	}

	// Apply updates field-by-field with nil checks
	if err := h.applyUpdate(bc, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	_, err = h.k8sClient.UpdateButlerConfigTyped(ctx, bc)
	if err != nil {
		h.logger.Error("Failed to update ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update platform configuration")
		return
	}

	// Re-read to return fresh state
	updated, err := h.k8sClient.GetButlerConfigTyped(ctx)
	if err != nil {
		h.logger.Error("Failed to re-read ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "config updated but failed to read back")
		return
	}

	// Sync audit emitter settings from updated config
	if h.auditEmitter != nil {
		h.auditEmitter.SetEnabled(updated.IsAuditEnabled())
		h.auditEmitter.SetWebhookURL(updated.GetAuditWebhookURL())
	}

	resp := h.buildResponse(updated)
	writeJSON(w, http.StatusOK, resp)
}

// --- Internal helpers ---

func (h *ConfigHandler) buildResponse(bc *butlerv1alpha1.ButlerConfig) ButlerConfigResponse {
	resp := ButlerConfigResponse{
		MultiTenancy: &MultiTenancyInfo{
			Mode: string(bc.Spec.MultiTenancy.Mode),
		},
		DefaultNamespace: bc.Spec.DefaultNamespace,
		Status: &ConfigStatusInfo{
			TeamCount:                bc.Status.TeamCount,
			ClusterCount:             bc.Status.ClusterCount,
			ControlPlaneExposureMode: string(bc.Status.ControlPlaneExposureMode),
			TCPProxyRequired:         bc.Status.TCPProxyRequired,
		},
		SSHAuthorizedKey: bc.Spec.SSHAuthorizedKey,
	}

	if bc.Spec.DefaultProviderConfigRef != nil {
		resp.DefaultProviderRef = &ProviderRefInfo{
			Name: bc.Spec.DefaultProviderConfigRef.Name,
		}
	}

	if bc.Spec.ControlPlaneExposure != nil {
		cpe := bc.Spec.ControlPlaneExposure
		resp.ControlPlaneExposure = &ControlPlaneExposureInfo{
			Mode:             string(cpe.Mode),
			Hostname:         cpe.Hostname,
			IngressClassName: cpe.IngressClassName,
			ControllerType:   cpe.ControllerType,
			GatewayRef:       cpe.GatewayRef,
		}
	}

	if bc.Spec.DefaultAddonVersions != nil {
		av := bc.Spec.DefaultAddonVersions
		resp.DefaultAddonVersions = &AddonVersionsInfo{
			Cilium:      av.Cilium,
			MetalLB:     av.MetalLB,
			CertManager: av.CertManager,
			Longhorn:    av.Longhorn,
			Traefik:     av.Traefik,
			FluxCD:      av.FluxCD,
		}
	}

	if bc.Spec.DefaultTeamLimits != nil {
		tl := bc.Spec.DefaultTeamLimits
		resp.DefaultTeamLimits = &TeamLimitsInfo{
			MaxClusters:          tl.MaxClusters,
			MaxWorkersPerCluster: tl.MaxWorkersPerCluster,
			MaxTotalCPU:          quantityToString(tl.MaxTotalCPU),
			MaxTotalMemory:       quantityToString(tl.MaxTotalMemory),
			MaxTotalStorage:      quantityToString(tl.MaxTotalStorage),
		}
	}

	if bc.Spec.DefaultControlPlaneResources != nil {
		cpr := bc.Spec.DefaultControlPlaneResources
		resp.DefaultControlPlaneResources = &CPResourcesInfo{}
		if cpr.APIServer != nil {
			resp.DefaultControlPlaneResources.APIServer = buildComponentResourcesInfo(cpr.APIServer)
		}
		if cpr.ControllerManager != nil {
			resp.DefaultControlPlaneResources.ControllerManager = buildComponentResourcesInfo(cpr.ControllerManager)
		}
		if cpr.Scheduler != nil {
			resp.DefaultControlPlaneResources.Scheduler = buildComponentResourcesInfo(cpr.Scheduler)
		}
	}

	if bc.Spec.Audit != nil {
		resp.Audit = &AuditInfo{
			Enabled:    bc.Spec.Audit.Enabled,
			WebhookURL: bc.Spec.Audit.WebhookURL,
			BufferSize: bc.Spec.Audit.BufferSize,
		}
	}

	if bc.Spec.ImageFactory != nil {
		ifConfig := bc.Spec.ImageFactory
		resp.ImageFactory = &ImageFactoryInfo{
			URL:                ifConfig.URL,
			DefaultSchematicID: ifConfig.DefaultSchematicID,
			AutoSync:           ifConfig.AutoSync,
		}
		if ifConfig.CredentialsRef != nil {
			resp.ImageFactory.CredentialsRef = ifConfig.CredentialsRef.Name
		}
	}

	return resp
}

func buildComponentResourcesInfo(cr *butlerv1alpha1.ComponentResources) *ComponentResourcesInfo {
	info := &ComponentResourcesInfo{}
	if cr.Requests != nil {
		info.Requests = &ResourceQuantitiesInfo{
			CPU:    quantityToString(cr.Requests.CPU),
			Memory: quantityToString(cr.Requests.Memory),
		}
	}
	if cr.Limits != nil {
		info.Limits = &ResourceQuantitiesInfo{
			CPU:    quantityToString(cr.Limits.CPU),
			Memory: quantityToString(cr.Limits.Memory),
		}
	}
	return info
}

func quantityToString(q *resource.Quantity) string {
	if q == nil {
		return ""
	}
	return q.String()
}

func parseQuantity(s string) (*resource.Quantity, error) {
	if s == "" {
		return nil, nil
	}
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return nil, fmt.Errorf("invalid resource quantity %q: %w", s, err)
	}
	return &q, nil
}

func (h *ConfigHandler) applyUpdate(bc *butlerv1alpha1.ButlerConfig, req *UpdateConfigRequest) error {
	if req.MultiTenancy != nil {
		bc.Spec.MultiTenancy.Mode = butlerv1alpha1.MultiTenancyMode(req.MultiTenancy.Mode)
	}

	if req.DefaultNamespace != nil {
		bc.Spec.DefaultNamespace = *req.DefaultNamespace
	}

	if req.DefaultProviderRef != nil {
		if req.DefaultProviderRef.Name == "" {
			bc.Spec.DefaultProviderConfigRef = nil
		} else {
			bc.Spec.DefaultProviderConfigRef = &butlerv1alpha1.LocalObjectReference{
				Name: req.DefaultProviderRef.Name,
			}
		}
	}

	if req.ControlPlaneExposure != nil {
		// Replace the entire section — empty strings clear the field.
		cpe := req.ControlPlaneExposure
		bc.Spec.ControlPlaneExposure = &butlerv1alpha1.ControlPlaneExposureSpec{
			Mode:             butlerv1alpha1.ControlPlaneExposureMode(cpe.Mode),
			Hostname:         cpe.Hostname,
			IngressClassName: cpe.IngressClassName,
			ControllerType:   cpe.ControllerType,
			GatewayRef:       cpe.GatewayRef,
		}
	}

	if req.DefaultAddonVersions != nil {
		// Replace the entire section — empty strings clear the field.
		bc.Spec.DefaultAddonVersions = &butlerv1alpha1.AddonVersions{
			Cilium:      req.DefaultAddonVersions.Cilium,
			MetalLB:     req.DefaultAddonVersions.MetalLB,
			CertManager: req.DefaultAddonVersions.CertManager,
			Longhorn:    req.DefaultAddonVersions.Longhorn,
			Traefik:     req.DefaultAddonVersions.Traefik,
			FluxCD:      req.DefaultAddonVersions.FluxCD,
		}
	}

	if req.DefaultTeamLimits != nil {
		// Replace the entire section — empty values clear the field.
		maxCPU, err := parseQuantity(req.DefaultTeamLimits.MaxTotalCPU)
		if err != nil {
			return fmt.Errorf("maxTotalCPU: %w", err)
		}
		maxMem, err := parseQuantity(req.DefaultTeamLimits.MaxTotalMemory)
		if err != nil {
			return fmt.Errorf("maxTotalMemory: %w", err)
		}
		maxStorage, err := parseQuantity(req.DefaultTeamLimits.MaxTotalStorage)
		if err != nil {
			return fmt.Errorf("maxTotalStorage: %w", err)
		}
		bc.Spec.DefaultTeamLimits = &butlerv1alpha1.ResourceLimits{
			MaxClusters:          req.DefaultTeamLimits.MaxClusters,
			MaxWorkersPerCluster: req.DefaultTeamLimits.MaxWorkersPerCluster,
			MaxTotalCPU:          maxCPU,
			MaxTotalMemory:       maxMem,
			MaxTotalStorage:      maxStorage,
		}
	}

	if req.DefaultControlPlaneResources != nil {
		// Replace the entire section — empty values clear the field.
		cpr, err := buildComponentResourcesValidated(req.DefaultControlPlaneResources)
		if err != nil {
			return fmt.Errorf("defaultControlPlaneResources: %w", err)
		}
		bc.Spec.DefaultControlPlaneResources = cpr
	}

	if req.ImageFactory != nil {
		// Replace the entire section — empty strings clear the field.
		ifCfg := &butlerv1alpha1.ImageFactoryConfig{
			URL:                req.ImageFactory.URL,
			DefaultSchematicID: req.ImageFactory.DefaultSchematicID,
			AutoSync:           req.ImageFactory.AutoSync,
		}
		if req.ImageFactory.CredentialsRef != "" {
			ifCfg.CredentialsRef = &butlerv1alpha1.SecretReference{
				Name: req.ImageFactory.CredentialsRef,
			}
		}
		bc.Spec.ImageFactory = ifCfg
	}

	if req.Audit != nil {
		bc.Spec.Audit = &butlerv1alpha1.AuditConfig{
			Enabled:    req.Audit.Enabled,
			WebhookURL: req.Audit.WebhookURL,
			BufferSize: req.Audit.BufferSize,
		}
	}

	if req.SSHAuthorizedKey != nil {
		bc.Spec.SSHAuthorizedKey = *req.SSHAuthorizedKey
	}

	return nil
}

func buildComponentResourcesValidated(source *CPResourcesInfo) (*butlerv1alpha1.ControlPlaneResourcesSpec, error) {
	apiServer, err := buildComponentResources(source.APIServer, "apiServer")
	if err != nil {
		return nil, err
	}
	cm, err := buildComponentResources(source.ControllerManager, "controllerManager")
	if err != nil {
		return nil, err
	}
	sched, err := buildComponentResources(source.Scheduler, "scheduler")
	if err != nil {
		return nil, err
	}
	return &butlerv1alpha1.ControlPlaneResourcesSpec{
		APIServer:         apiServer,
		ControllerManager: cm,
		Scheduler:         sched,
	}, nil
}

func buildComponentResources(source *ComponentResourcesInfo, name string) (*butlerv1alpha1.ComponentResources, error) {
	if source == nil {
		return nil, nil
	}
	cr := &butlerv1alpha1.ComponentResources{}
	if source.Requests != nil {
		cpu, err := parseQuantity(source.Requests.CPU)
		if err != nil {
			return nil, fmt.Errorf("%s.requests.cpu: %w", name, err)
		}
		mem, err := parseQuantity(source.Requests.Memory)
		if err != nil {
			return nil, fmt.Errorf("%s.requests.memory: %w", name, err)
		}
		cr.Requests = &butlerv1alpha1.ResourceQuantities{CPU: cpu, Memory: mem}
	}
	if source.Limits != nil {
		cpu, err := parseQuantity(source.Limits.CPU)
		if err != nil {
			return nil, fmt.Errorf("%s.limits.cpu: %w", name, err)
		}
		mem, err := parseQuantity(source.Limits.Memory)
		if err != nil {
			return nil, fmt.Errorf("%s.limits.memory: %w", name, err)
		}
		cr.Limits = &butlerv1alpha1.ResourceQuantities{CPU: cpu, Memory: mem}
	}
	return cr, nil
}
