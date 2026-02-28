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
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	butlerv1alpha1 "github.com/butlerdotdev/butler-api/api/v1alpha1"
	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"
)

// ObservabilityHandler handles observability-related API requests.
type ObservabilityHandler struct {
	k8sClient *k8s.Client
	config    *config.Config
	logger    *slog.Logger
}

// NewObservabilityHandler creates a new observability handler.
func NewObservabilityHandler(k8sClient *k8s.Client, cfg *config.Config, logger *slog.Logger) *ObservabilityHandler {
	return &ObservabilityHandler{
		k8sClient: k8sClient,
		config:    cfg,
		logger:    logger,
	}
}

// --- Request/Response Types ---

// ObservabilityConfigResponse is the API response for observability configuration.
type ObservabilityConfigResponse struct {
	Configured bool                 `json:"configured"`
	Pipeline   *PipelineConfigInfo  `json:"pipeline,omitempty"`
	Collection *CollectionConfigInfo `json:"collection,omitempty"`
}

// PipelineConfigInfo contains pipeline configuration details.
type PipelineConfigInfo struct {
	ClusterName      string `json:"clusterName,omitempty"`
	ClusterNamespace string `json:"clusterNamespace,omitempty"`
	LogEndpoint      string `json:"logEndpoint,omitempty"`
	MetricEndpoint   string `json:"metricEndpoint,omitempty"`
	TraceEndpoint    string `json:"traceEndpoint,omitempty"`
}

// CollectionConfigInfo contains collection defaults.
type CollectionConfigInfo struct {
	AutoEnroll bool                  `json:"autoEnroll"`
	Logs       *LogCollectionInfo    `json:"logs,omitempty"`
	Metrics    *MetricCollectionInfo `json:"metrics,omitempty"`
}

// LogCollectionInfo contains log collection settings.
type LogCollectionInfo struct {
	PodLogs          bool `json:"podLogs"`
	Journald         bool `json:"journald"`
	KubernetesEvents bool `json:"kubernetesEvents"`
}

// MetricCollectionInfo contains metric collection settings.
type MetricCollectionInfo struct {
	Enabled   bool   `json:"enabled"`
	Retention string `json:"retention,omitempty"`
}

// ObservabilityStatusResponse is the API response for fleet observability status.
type ObservabilityStatusResponse struct {
	Pipeline *PipelineStatusInfo  `json:"pipeline,omitempty"`
	Clusters []ClusterObsInfo     `json:"clusters"`
	Summary  ObservabilitySummary `json:"summary"`
}

// PipelineStatusInfo contains pipeline cluster status.
type PipelineStatusInfo struct {
	ClusterName      string `json:"clusterName"`
	ClusterNamespace string `json:"clusterNamespace"`
	ClusterPhase     string `json:"clusterPhase"`
	LogEndpoint      string `json:"logEndpoint"`
	AggregatorStatus string `json:"aggregatorStatus,omitempty"`
}

// ClusterObsInfo contains per-cluster observability information.
type ClusterObsInfo struct {
	Name          string           `json:"name"`
	Namespace     string           `json:"namespace"`
	Team          string           `json:"team"`
	Phase         string           `json:"phase"`
	VectorAgent   *AddonStatusInfo `json:"vectorAgent,omitempty"`
	Prometheus    *AddonStatusInfo `json:"prometheus,omitempty"`
	OtelCollector *AddonStatusInfo `json:"otelCollector,omitempty"`
}

// AddonStatusInfo contains addon status and version.
type AddonStatusInfo struct {
	Status  string `json:"status"`
	Version string `json:"version,omitempty"`
}

// ObservabilitySummary contains aggregate fleet stats.
type ObservabilitySummary struct {
	TotalClusters      int `json:"totalClusters"`
	EnrolledClusters   int `json:"enrolledClusters"`
	VectorAgentCount   int `json:"vectorAgentCount"`
	PrometheusCount    int `json:"prometheusCount"`
	OtelCollectorCount int `json:"otelCollectorCount"`
}

// SetupPipelineRequest is the request body for pipeline registration.
type SetupPipelineRequest struct {
	ClusterName      string `json:"clusterName"`
	ClusterNamespace string `json:"clusterNamespace"`
	LogEndpoint      string `json:"logEndpoint"`
	MetricEndpoint   string `json:"metricEndpoint,omitempty"`
	TraceEndpoint    string `json:"traceEndpoint,omitempty"`
}

// UpdateObservabilityConfigRequest is the request body for config updates.
type UpdateObservabilityConfigRequest struct {
	Pipeline   *PipelineConfigInfo   `json:"pipeline,omitempty"`
	Collection *CollectionConfigInfo `json:"collection,omitempty"`
}

// --- Handlers ---

// GetConfig returns the current observability configuration.
// Any authenticated user can read this.
func (h *ObservabilityHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	bc, err := h.k8sClient.GetButlerConfigTyped(ctx)
	if err != nil {
		h.logger.Error("Failed to get ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get platform configuration")
		return
	}

	resp := h.buildConfigResponse(bc)

	// If config says configured, verify the pipeline cluster still exists
	if resp.Configured && bc.Spec.Observability != nil && bc.Spec.Observability.Pipeline != nil &&
		bc.Spec.Observability.Pipeline.ClusterRef != nil {
		ref := bc.Spec.Observability.Pipeline.ClusterRef
		_, err := h.k8sClient.GetTenantClusterTyped(ctx, ref.Namespace, ref.Name)
		if err != nil {
			h.logger.Warn("Pipeline cluster no longer exists, clearing config",
				"cluster", ref.Name, "namespace", ref.Namespace)
			// Clear the stale pipeline reference
			bc.Spec.Observability.Pipeline = nil
			if _, updateErr := h.k8sClient.UpdateButlerConfigTyped(ctx, bc); updateErr != nil {
				h.logger.Error("Failed to clear stale pipeline config", "error", updateErr)
			}
			resp.Configured = false
			resp.Pipeline = nil
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// UpdateConfig updates the observability configuration. Admin only.
func (h *ObservabilityHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req UpdateObservabilityConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate endpoint URLs if provided
	if req.Pipeline != nil {
		if req.Pipeline.LogEndpoint != "" {
			if err := validateEndpointURL(req.Pipeline.LogEndpoint); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid log endpoint: %s", err))
				return
			}
		}
		if req.Pipeline.MetricEndpoint != "" {
			if err := validateEndpointURL(req.Pipeline.MetricEndpoint); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid metric endpoint: %s", err))
				return
			}
		}
		if req.Pipeline.TraceEndpoint != "" {
			if err := validateEndpointURL(req.Pipeline.TraceEndpoint); err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid trace endpoint: %s", err))
				return
			}
		}
	}

	// Validate cluster reference if provided
	if req.Pipeline != nil && req.Pipeline.ClusterName != "" {
		_, err := h.k8sClient.GetTenantClusterTyped(ctx, req.Pipeline.ClusterNamespace, req.Pipeline.ClusterName)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("pipeline cluster not found: %s/%s", req.Pipeline.ClusterNamespace, req.Pipeline.ClusterName))
			return
		}
	}

	bc, err := h.k8sClient.GetButlerConfigTyped(ctx)
	if err != nil {
		h.logger.Error("Failed to get ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get platform configuration")
		return
	}

	// Apply updates
	h.applyConfigUpdate(bc, &req)

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

	resp := h.buildConfigResponse(updated)
	writeJSON(w, http.StatusOK, resp)
}

// DeregisterPipeline clears the observability pipeline configuration. Admin only.
func (h *ObservabilityHandler) DeregisterPipeline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	bc, err := h.k8sClient.GetButlerConfigTyped(ctx)
	if err != nil {
		h.logger.Error("Failed to get ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get platform configuration")
		return
	}

	// Remove pipeline label from the old cluster before clearing config
	if bc.Spec.Observability != nil && bc.Spec.Observability.Pipeline != nil &&
		bc.Spec.Observability.Pipeline.ClusterRef != nil {
		ref := bc.Spec.Observability.Pipeline.ClusterRef
		removeLabelPatch := []byte(`{"metadata":{"labels":{"butler.butlerlabs.dev/observability-pipeline":null}}}`)
		if _, patchErr := h.k8sClient.PatchTenantCluster(ctx, ref.Namespace, ref.Name, removeLabelPatch); patchErr != nil {
			h.logger.Warn("Failed to remove pipeline label from old cluster",
				"cluster", ref.Name, "namespace", ref.Namespace, "error", patchErr)
		}
	}

	if bc.Spec.Observability != nil {
		bc.Spec.Observability.Pipeline = nil
	}

	_, err = h.k8sClient.UpdateButlerConfigTyped(ctx, bc)
	if err != nil {
		h.logger.Error("Failed to update ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to clear pipeline configuration")
		return
	}

	updated, err := h.k8sClient.GetButlerConfigTyped(ctx)
	if err != nil {
		h.logger.Error("Failed to re-read ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "pipeline cleared but failed to read back")
		return
	}

	resp := h.buildConfigResponse(updated)
	writeJSON(w, http.StatusOK, resp)
}

// GetStatus returns aggregated fleet observability status. Admin only.
//
// Note: This makes O(n) K8s API calls where n is the number of tenant clusters,
// one ListTenantAddons call per cluster. Acceptable for current scale but will
// need optimization (e.g., label-based cross-namespace list) at larger fleet sizes.
func (h *ObservabilityHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	bc, err := h.k8sClient.GetButlerConfigTyped(ctx)
	if err != nil {
		h.logger.Error("Failed to get ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get platform configuration")
		return
	}

	// List all tenant clusters across all namespaces
	tcList, err := h.k8sClient.ListTenantClustersTyped(ctx, "")
	if err != nil {
		h.logger.Error("Failed to list tenant clusters", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list tenant clusters")
		return
	}

	var (
		clusters           []ClusterObsInfo
		enrolledCount      int
		vectorAgentCount   int
		prometheusCount    int
		otelCollectorCount int
	)

	for _, tc := range tcList.Items {
		info := ClusterObsInfo{
			Name:      tc.Name,
			Namespace: tc.Namespace,
			Team:      tc.Labels[butlerv1alpha1.LabelTeam],
			Phase:     string(tc.Status.Phase),
		}

		// List addons for this cluster
		addons, err := h.k8sClient.ListTenantAddons(ctx, tc.Namespace, tc.Name)
		if err != nil {
			h.logger.Warn("Failed to list addons for cluster",
				"cluster", tc.Name, "namespace", tc.Namespace, "error", err)
			clusters = append(clusters, info)
			continue
		}

		enrolled := false
		for _, addon := range addons.Items {
			addonName, _, _ := strings.Cut(addon.GetName(), ".")
			specAddon, _, _ := getNestedString(addon.Object, "spec", "addon")

			phase, _, _ := getNestedString(addon.Object, "status", "phase")
			version, _, _ := getNestedString(addon.Object, "spec", "version")
			installedVersion, _, _ := getNestedString(addon.Object, "status", "installedVersion")
			if installedVersion != "" {
				version = installedVersion
			}

			statusInfo := &AddonStatusInfo{
				Status:  MapAddonStatus(phase),
				Version: version,
			}

			isNonDeleting := phase != "Deleting"

			if isVectorAgent(specAddon, addonName) {
				info.VectorAgent = statusInfo
				if isNonDeleting {
					enrolled = true
					vectorAgentCount++
				}
			} else if isPrometheus(specAddon, addonName) {
				info.Prometheus = statusInfo
				if isNonDeleting {
					enrolled = true
					prometheusCount++
				}
			} else if isOtelCollector(specAddon, addonName) {
				info.OtelCollector = statusInfo
				if isNonDeleting {
					enrolled = true
					otelCollectorCount++
				}
			}
		}

		if enrolled {
			enrolledCount++
		}

		clusters = append(clusters, info)
	}

	resp := ObservabilityStatusResponse{
		Clusters: clusters,
		Summary: ObservabilitySummary{
			TotalClusters:      len(tcList.Items),
			EnrolledClusters:   enrolledCount,
			VectorAgentCount:   vectorAgentCount,
			PrometheusCount:    prometheusCount,
			OtelCollectorCount: otelCollectorCount,
		},
	}

	// Add pipeline status if configured
	if bc.IsObservabilityConfigured() {
		pipeline := bc.Spec.Observability.Pipeline
		pipelineInfo := &PipelineStatusInfo{
			ClusterName:      pipeline.ClusterRef.Name,
			ClusterNamespace: pipeline.ClusterRef.Namespace,
			LogEndpoint:      pipeline.LogEndpoint,
		}

		// Get pipeline cluster phase
		pipelineTC, err := h.k8sClient.GetTenantClusterTyped(ctx, pipeline.ClusterRef.Namespace, pipeline.ClusterRef.Name)
		if err != nil {
			h.logger.Warn("Failed to get pipeline cluster", "error", err)
			pipelineInfo.ClusterPhase = "Unknown"
		} else {
			pipelineInfo.ClusterPhase = string(pipelineTC.Status.Phase)

			// Check aggregator status: first try TenantAddon, then probe the endpoint
			aggregatorFound := false
			pipelineAddons, err := h.k8sClient.ListTenantAddons(ctx, pipeline.ClusterRef.Namespace, pipeline.ClusterRef.Name)
			if err == nil {
				for _, addon := range pipelineAddons.Items {
					addonName, _, _ := strings.Cut(addon.GetName(), ".")
					specAddon, _, _ := getNestedString(addon.Object, "spec", "addon")
					if isVectorAggregator(specAddon, addonName) {
						phase, _, _ := getNestedString(addon.Object, "status", "phase")
						pipelineInfo.AggregatorStatus = MapAddonStatus(phase)
						aggregatorFound = true
						break
					}
				}
			}

			// No TenantAddon found — probe the log endpoint host for a Vector health check.
			// Vector exposes /health on its API port (8686 by default).
			if !aggregatorFound && pipeline.LogEndpoint != "" {
				pipelineInfo.AggregatorStatus = probeAggregatorHealth(pipeline.LogEndpoint)
			}
		}

		resp.Pipeline = pipelineInfo
	}

	// Backfill ButlerConfig observability status with computed values
	if bc.Spec.Observability != nil {
		if bc.Status.Observability == nil {
			bc.Status.Observability = &butlerv1alpha1.ObservabilityStatus{}
		}
		bc.Status.Observability.EnrolledCount = int32(enrolledCount)
		bc.Status.Observability.TotalCount = int32(len(tcList.Items))
		bc.Status.Observability.PipelineReady = resp.Pipeline != nil &&
			resp.Pipeline.ClusterPhase == "Ready"
		if _, updateErr := h.k8sClient.UpdateButlerConfigStatusTyped(ctx, bc); updateErr != nil {
			h.logger.Warn("Failed to update ButlerConfig observability status", "error", updateErr)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// SetupPipeline registers an existing cluster as the observability pipeline. Admin only.
func (h *ObservabilityHandler) SetupPipeline(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SetupPipelineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ClusterName == "" || req.ClusterNamespace == "" {
		writeError(w, http.StatusBadRequest, "clusterName and clusterNamespace are required")
		return
	}
	if req.LogEndpoint == "" {
		writeError(w, http.StatusBadRequest, "logEndpoint is required")
		return
	}

	if err := validateEndpointURL(req.LogEndpoint); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid log endpoint: %s", err))
		return
	}
	if req.MetricEndpoint != "" {
		if err := validateEndpointURL(req.MetricEndpoint); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid metric endpoint: %s", err))
			return
		}
	}
	if req.TraceEndpoint != "" {
		if err := validateEndpointURL(req.TraceEndpoint); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid trace endpoint: %s", err))
			return
		}
	}

	// Validate cluster exists and is Ready
	tc, err := h.k8sClient.GetTenantClusterTyped(ctx, req.ClusterNamespace, req.ClusterName)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("cluster not found: %s/%s", req.ClusterNamespace, req.ClusterName))
		return
	}
	if tc.Status.Phase != butlerv1alpha1.TenantClusterPhaseReady {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("cluster is not Ready (current phase: %s)", tc.Status.Phase))
		return
	}

	// Get ButlerConfig to check for existing pipeline
	bc, err := h.k8sClient.GetButlerConfigTyped(ctx)
	if err != nil {
		h.logger.Error("Failed to get ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get platform configuration")
		return
	}

	// Remove pipeline label from old cluster if switching pipelines
	if bc.Spec.Observability != nil && bc.Spec.Observability.Pipeline != nil &&
		bc.Spec.Observability.Pipeline.ClusterRef != nil {
		oldRef := bc.Spec.Observability.Pipeline.ClusterRef
		if oldRef.Name != req.ClusterName || oldRef.Namespace != req.ClusterNamespace {
			removeLabelPatch := []byte(`{"metadata":{"labels":{"butler.butlerlabs.dev/observability-pipeline":null}}}`)
			if _, patchErr := h.k8sClient.PatchTenantCluster(ctx, oldRef.Namespace, oldRef.Name, removeLabelPatch); patchErr != nil {
				h.logger.Warn("Failed to remove pipeline label from old cluster",
					"cluster", oldRef.Name, "namespace", oldRef.Namespace, "error", patchErr)
			}
		}
	}

	// Label the new pipeline cluster for discoverability
	labelPatch := []byte(`{"metadata":{"labels":{"butler.butlerlabs.dev/observability-pipeline":"true"}}}`)
	if _, patchErr := h.k8sClient.PatchTenantCluster(ctx, req.ClusterNamespace, req.ClusterName, labelPatch); patchErr != nil {
		h.logger.Error("Failed to label pipeline cluster", "error", patchErr)
		writeError(w, http.StatusInternalServerError, "failed to label pipeline cluster")
		return
	}

	if bc.Spec.Observability == nil {
		bc.Spec.Observability = &butlerv1alpha1.ObservabilityConfig{}
	}
	bc.Spec.Observability.Pipeline = &butlerv1alpha1.ObservabilityPipelineConfig{
		ClusterRef: &butlerv1alpha1.NamespacedObjectReference{
			Name:      req.ClusterName,
			Namespace: req.ClusterNamespace,
		},
		LogEndpoint:    req.LogEndpoint,
		MetricEndpoint: req.MetricEndpoint,
		TraceEndpoint:  req.TraceEndpoint,
	}

	_, err = h.k8sClient.UpdateButlerConfigTyped(ctx, bc)
	if err != nil {
		h.logger.Error("Failed to update ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update platform configuration")
		return
	}

	// Re-read and return
	updated, err := h.k8sClient.GetButlerConfigTyped(ctx)
	if err != nil {
		h.logger.Error("Failed to re-read ButlerConfig", "error", err)
		writeError(w, http.StatusInternalServerError, "pipeline registered but failed to read back config")
		return
	}

	resp := h.buildConfigResponse(updated)
	writeJSON(w, http.StatusOK, resp)
}

// --- Internal helpers ---

func (h *ObservabilityHandler) buildConfigResponse(bc *butlerv1alpha1.ButlerConfig) ObservabilityConfigResponse {
	resp := ObservabilityConfigResponse{
		Configured: bc.IsObservabilityConfigured(),
	}

	if bc.Spec.Observability == nil {
		return resp
	}

	obs := bc.Spec.Observability

	if obs.Pipeline != nil {
		resp.Pipeline = &PipelineConfigInfo{
			LogEndpoint:    obs.Pipeline.LogEndpoint,
			MetricEndpoint: obs.Pipeline.MetricEndpoint,
			TraceEndpoint:  obs.Pipeline.TraceEndpoint,
		}
		if obs.Pipeline.ClusterRef != nil {
			resp.Pipeline.ClusterName = obs.Pipeline.ClusterRef.Name
			resp.Pipeline.ClusterNamespace = obs.Pipeline.ClusterRef.Namespace
		}
	}

	if obs.Collection != nil {
		resp.Collection = &CollectionConfigInfo{
			AutoEnroll: obs.Collection.AutoEnroll,
		}
		if obs.Collection.Logs != nil {
			resp.Collection.Logs = &LogCollectionInfo{
				PodLogs:          obs.Collection.Logs.PodLogs,
				Journald:         obs.Collection.Logs.Journald,
				KubernetesEvents: obs.Collection.Logs.KubernetesEvents,
			}
		}
		if obs.Collection.Metrics != nil {
			resp.Collection.Metrics = &MetricCollectionInfo{
				Enabled:   obs.Collection.Metrics.Enabled,
				Retention: obs.Collection.Metrics.Retention,
			}
		}
	}

	return resp
}

func (h *ObservabilityHandler) applyConfigUpdate(bc *butlerv1alpha1.ButlerConfig, req *UpdateObservabilityConfigRequest) {
	if bc.Spec.Observability == nil {
		bc.Spec.Observability = &butlerv1alpha1.ObservabilityConfig{}
	}

	if req.Pipeline != nil {
		if bc.Spec.Observability.Pipeline == nil {
			bc.Spec.Observability.Pipeline = &butlerv1alpha1.ObservabilityPipelineConfig{}
		}
		if req.Pipeline.ClusterName != "" {
			bc.Spec.Observability.Pipeline.ClusterRef = &butlerv1alpha1.NamespacedObjectReference{
				Name:      req.Pipeline.ClusterName,
				Namespace: req.Pipeline.ClusterNamespace,
			}
		}
		if req.Pipeline.LogEndpoint != "" {
			bc.Spec.Observability.Pipeline.LogEndpoint = req.Pipeline.LogEndpoint
		}
		if req.Pipeline.MetricEndpoint != "" {
			bc.Spec.Observability.Pipeline.MetricEndpoint = req.Pipeline.MetricEndpoint
		}
		if req.Pipeline.TraceEndpoint != "" {
			bc.Spec.Observability.Pipeline.TraceEndpoint = req.Pipeline.TraceEndpoint
		}
	}

	if req.Collection != nil {
		if bc.Spec.Observability.Collection == nil {
			bc.Spec.Observability.Collection = &butlerv1alpha1.ObservabilityCollectionConfig{}
		}
		bc.Spec.Observability.Collection.AutoEnroll = req.Collection.AutoEnroll
		if req.Collection.Logs != nil {
			bc.Spec.Observability.Collection.Logs = &butlerv1alpha1.LogCollectionDefaults{
				PodLogs:          req.Collection.Logs.PodLogs,
				Journald:         req.Collection.Logs.Journald,
				KubernetesEvents: req.Collection.Logs.KubernetesEvents,
			}
		}
		if req.Collection.Metrics != nil {
			bc.Spec.Observability.Collection.Metrics = &butlerv1alpha1.MetricCollectionDefaults{
				Enabled:   req.Collection.Metrics.Enabled,
				Retention: req.Collection.Metrics.Retention,
			}
		}
	}
}

func validateEndpointURL(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("URL must include scheme and host (e.g., http://host:port)")
	}
	return nil
}

// getNestedString safely extracts a nested string value from an unstructured map.
func getNestedString(obj map[string]interface{}, fields ...string) (string, bool, error) {
	current := obj
	for i, field := range fields {
		if i == len(fields)-1 {
			val, ok := current[field]
			if !ok {
				return "", false, nil
			}
			s, ok := val.(string)
			if !ok {
				return "", false, fmt.Errorf("field %s is not a string", field)
			}
			return s, true, nil
		}
		next, ok := current[field]
		if !ok {
			return "", false, nil
		}
		nested, ok := next.(map[string]interface{})
		if !ok {
			return "", false, fmt.Errorf("field %s is not a map", field)
		}
		current = nested
	}
	return "", false, nil
}

// isVectorAgent checks if an addon is the vector-agent by spec.addon or metadata.name.
func isVectorAgent(specAddon, metadataName string) bool {
	return strings.EqualFold(specAddon, "vector-agent") || strings.EqualFold(metadataName, "vector-agent")
}

// isVectorAggregator checks if an addon is the vector-aggregator.
func isVectorAggregator(specAddon, metadataName string) bool {
	return strings.EqualFold(specAddon, "vector-aggregator") || strings.EqualFold(metadataName, "vector-aggregator")
}

// isOtelCollector checks if an addon is the otel-collector.
func isOtelCollector(specAddon, metadataName string) bool {
	return strings.EqualFold(specAddon, "otel-collector") || strings.EqualFold(metadataName, "otel-collector")
}

// isPrometheus checks if an addon is the prometheus-operator / kube-prometheus-stack.
func isPrometheus(specAddon, metadataName string) bool {
	return strings.EqualFold(specAddon, "prometheus-operator") || strings.EqualFold(metadataName, "prometheus-operator") ||
		strings.EqualFold(specAddon, "kube-prometheus-stack") || strings.EqualFold(metadataName, "kube-prometheus-stack")
}

// probeAggregatorHealth checks if the aggregator is reachable by hitting the Vector API
// health endpoint (/health on port 8686) derived from the log endpoint host.
func probeAggregatorHealth(logEndpoint string) string {
	u, err := url.Parse(logEndpoint)
	if err != nil {
		return "Unknown"
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}

	healthURL := fmt.Sprintf("http://%s:8686/health", host)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		return "Unreachable"
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "Healthy"
	}
	return "Degraded"
}
