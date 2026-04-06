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
	"net/http"

	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"
	"github.com/go-chi/chi/v5"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// StewardHandler handles TenantControlPlane and DataStore visibility endpoints.
type StewardHandler struct {
	k8sClient *k8s.Client
	config    *config.Config
}

// NewStewardHandler creates a new Steward handler.
func NewStewardHandler(k8sClient *k8s.Client, cfg *config.Config) *StewardHandler {
	return &StewardHandler{
		k8sClient: k8sClient,
		config:    cfg,
	}
}

// ListTenantControlPlanes returns all TCPs across all namespaces.
func (h *StewardHandler) ListTenantControlPlanes(w http.ResponseWriter, r *http.Request) {
	tcpList, err := h.k8sClient.ListTenantControlPlanes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list TenantControlPlanes: "+err.Error())
		return
	}

	result := make([]map[string]interface{}, 0, len(tcpList.Items))
	for _, tcp := range tcpList.Items {
		result = append(result, buildTCPResponse(&tcp))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"tenantControlPlanes": result,
	})
}

// GetTenantControlPlane returns a specific TCP.
func (h *StewardHandler) GetTenantControlPlane(w http.ResponseWriter, r *http.Request) {
	ns := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	tcp, err := h.k8sClient.GetTenantControlPlane(r.Context(), ns, name)
	if err != nil {
		writeError(w, http.StatusNotFound, "TenantControlPlane not found")
		return
	}

	writeJSON(w, http.StatusOK, buildTCPResponse(tcp))
}

// GetClusterTenantControlPlane returns the TCP associated with a TenantCluster.
func (h *StewardHandler) GetClusterTenantControlPlane(w http.ResponseWriter, r *http.Request) {
	clusterNS := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")

	tc, err := h.k8sClient.GetTenantCluster(r.Context(), clusterNS, clusterName)
	if err != nil {
		writeError(w, http.StatusNotFound, "TenantCluster not found")
		return
	}

	tenantNS, _, _ := unstructured.NestedString(tc.Object, "status", "tenantNamespace")
	if tenantNS == "" {
		writeError(w, http.StatusNotFound, "TenantCluster has no tenant namespace")
		return
	}

	tcp, err := h.k8sClient.GetTenantControlPlane(r.Context(), tenantNS, clusterName)
	if err != nil {
		writeError(w, http.StatusNotFound, "TenantControlPlane not found for cluster")
		return
	}

	writeJSON(w, http.StatusOK, buildTCPResponse(tcp))
}

// ListDataStores returns all DataStores.
func (h *StewardHandler) ListDataStores(w http.ResponseWriter, r *http.Request) {
	dsList, err := h.k8sClient.ListDataStores(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list DataStores: "+err.Error())
		return
	}

	result := make([]map[string]interface{}, 0, len(dsList.Items))
	for _, ds := range dsList.Items {
		result = append(result, buildDataStoreResponse(&ds))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"datastores": result,
	})
}

// GetDataStore returns a specific DataStore.
func (h *StewardHandler) GetDataStore(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	ds, err := h.k8sClient.GetDataStore(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "DataStore not found")
		return
	}

	writeJSON(w, http.StatusOK, buildDataStoreResponse(ds))
}

func buildTCPResponse(tcp *unstructured.Unstructured) map[string]interface{} {
	version, _, _ := unstructured.NestedString(tcp.Object, "status", "kubernetesResources", "version", "version")
	phase, _, _ := unstructured.NestedString(tcp.Object, "status", "kubernetesResources", "version", "status")
	endpoint, _, _ := unstructured.NestedString(tcp.Object, "status", "controlPlaneEndpoint")

	replicas, _, _ := unstructured.NestedInt64(tcp.Object, "status", "kubernetesResources", "deployment", "replicas")
	readyReplicas, _, _ := unstructured.NestedInt64(tcp.Object, "status", "kubernetesResources", "deployment", "readyReplicas")

	svcPort, _, _ := unstructured.NestedInt64(tcp.Object, "status", "kubernetesResources", "service", "port")
	lbIP := ""
	ingress, found, _ := unstructured.NestedSlice(tcp.Object, "status", "kubernetesResources", "service", "loadBalancer", "ingress")
	if found && len(ingress) > 0 {
		if entry, ok := ingress[0].(map[string]interface{}); ok {
			lbIP, _, _ = unstructured.NestedString(entry, "ip")
		}
	}

	dsName, _, _ := unstructured.NestedString(tcp.Object, "status", "storage", "dataStoreName")
	dsDriver, _, _ := unstructured.NestedString(tcp.Object, "status", "storage", "driver")

	konnEnabled, _, _ := unstructured.NestedBool(tcp.Object, "status", "addons", "konnectivity", "enabled")
	bootstrapEndpoint, _, _ := unstructured.NestedString(tcp.Object, "status", "addons", "workerBootstrap", "endpoint")
	bootstrapProvider, _, _ := unstructured.NestedString(tcp.Object, "status", "addons", "workerBootstrap", "provider")

	specVersion, _, _ := unstructured.NestedString(tcp.Object, "spec", "kubernetes", "version")

	return map[string]interface{}{
		"name":      tcp.GetName(),
		"namespace": tcp.GetNamespace(),
		"specVersion": specVersion,
		"status": map[string]interface{}{
			"phase":                phase,
			"version":              version,
			"controlPlaneEndpoint": endpoint,
			"replicas":             replicas,
			"readyReplicas":        readyReplicas,
			"servicePort":          svcPort,
			"loadBalancerIP":       lbIP,
			"dataStoreName":        dsName,
			"dataStoreDriver":      dsDriver,
			"konnectivityEnabled":  konnEnabled,
			"workerBootstrap": map[string]interface{}{
				"provider": bootstrapProvider,
				"endpoint": bootstrapEndpoint,
			},
		},
	}
}

func buildDataStoreResponse(ds *unstructured.Unstructured) map[string]interface{} {
	driver, _, _ := unstructured.NestedString(ds.Object, "spec", "driver")

	endpoints, _, _ := unstructured.NestedStringSlice(ds.Object, "spec", "endpoints")

	usedBy, _, _ := unstructured.NestedStringSlice(ds.Object, "status", "usedBy")

	return map[string]interface{}{
		"name":      ds.GetName(),
		"driver":    driver,
		"endpoints": endpoints,
		"usedBy":    usedBy,
	}
}
