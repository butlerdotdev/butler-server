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

package gitops

import (
	"context"
	"fmt"
	"log/slog"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// NamespaceMetadata captures the labels and annotations of a live Namespace
// object. Used by layout v2 to emit Namespace YAML that preserves the
// cluster's actual metadata (pod-security labels, network policy labels,
// owner annotations) rather than synthesizing a bare Namespace with only
// the name field.
//
// Tenant clusters depend on this — workload namespaces routinely carry
// labels for pod-security profiles, network-policy targeting, and
// observability scrape selection. A bare Namespace replaces those with
// nothing, which is a real regression.
type NamespaceMetadata struct {
	Labels      map[string]string
	Annotations map[string]string
}

// NamespaceMetadataMap is a per-namespace-name lookup of metadata for
// every namespace the export's emitted releases or native resources
// reference. Layout v2 consults this map when emitting Namespace YAML.
type NamespaceMetadataMap map[string]*NamespaceMetadata

// DiscoverNamespaceMetadata fetches labels and annotations for every
// namespace named in the supplied set. The set is populated from
// discovered HelmReleases' targetNamespaces plus any namespaced native
// resources the export will emit.
//
// Read-only: only Get is called. Missing namespaces (Get returns NotFound)
// are skipped silently; the layout falls back to emitting a bare Namespace
// for those.
func DiscoverNamespaceMetadata(ctx context.Context, kubeconfig []byte, names map[string]bool) (NamespaceMetadataMap, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	out := make(NamespaceMetadataMap, len(names))
	for name := range names {
		if name == "" {
			continue
		}
		ns, err := clientset.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			slog.Debug("namespace metadata fetch skipped", "namespace", name, "error", err)
			continue
		}
		out[name] = &NamespaceMetadata{
			Labels:      filterServerLabels(ns.Labels),
			Annotations: filterServerAnnotations(ns.Annotations),
		}
	}
	return out, nil
}

// isRuntimeLabel reports whether a metadata.labels key is added by the
// API server or a cluster controller and should not appear in a
// declarative export. Single source of truth for the LABEL filter,
// used by both the namespace-enrichment path and the inventory-walk
// path. Operator-declared labels (e.g. strimzi.io/cluster) are NOT in
// this set and pass through.
func isRuntimeLabel(key string) bool {
	if key == "kubernetes.io/metadata.name" {
		return true
	}
	// Flux stamps ownership as both labels and annotations. The label
	// form participates in Flux's adoption logic; if it's left in the
	// exported tree pointing at the old Kustomization name, Flux
	// rewrites it on first reconcile of the new tree. Operator-visible
	// churn rather than corruption, but inconsistent with the
	// declarative-export stance, so strip.
	if hasPrefix(key, "kustomize.toolkit.fluxcd.io/") ||
		hasPrefix(key, "reconcile.fluxcd.io/") ||
		hasPrefix(key, "fluxcd.io/") {
		return true
	}
	return false
}

// isRuntimeAnnotation reports whether a metadata.annotations key is
// controller-managed runtime state. Same role as isRuntimeLabel for
// the annotation set.
func isRuntimeAnnotation(key string) bool {
	if hasPrefix(key, "kustomize.toolkit.fluxcd.io/") ||
		hasPrefix(key, "reconcile.fluxcd.io/") ||
		hasPrefix(key, "fluxcd.io/") {
		return true
	}
	// Helm release tracking — meta.helm.sh/release-name and
	// meta.helm.sh/release-namespace are stamped by the helm controller
	// at install time, never declared by the operator.
	if hasPrefix(key, "meta.helm.sh/") {
		return true
	}
	// Server-side apply field manager metadata
	if key == "kubectl.kubernetes.io/last-applied-configuration" {
		return true
	}
	return false
}

// filterServerLabels removes runtime labels per the isRuntimeLabel
// predicate. Used by the namespace-enrichment emission path.
func filterServerLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if isRuntimeLabel(k) {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// filterServerAnnotations removes runtime annotations per the
// isRuntimeAnnotation predicate. Used by the namespace-enrichment
// emission path.
func filterServerAnnotations(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if isRuntimeAnnotation(k) {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func hasPrefix(s, p string) bool {
	if len(s) < len(p) {
		return false
	}
	return s[:len(p)] == p
}

// namespaceFromDiscovery returns a K8sNamespace populated from the
// discovered NamespaceMetadata if available, falling back to a bare
// Namespace when no metadata was discovered (e.g., the namespace is
// not present on the cluster yet — chart will createNamespace at
// install time).
func namespaceFromDiscovery(name string, meta *NamespaceMetadata) *K8sNamespace {
	ns := NewK8sNamespace(name)
	if meta != nil {
		ns.Metadata.Labels = meta.Labels
		ns.Metadata.Annotations = meta.Annotations
	}
	return ns
}
