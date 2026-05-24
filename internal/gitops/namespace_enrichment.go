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

// filterServerLabels removes labels the API server or kubernetes runtime
// adds and that should not appear in a declarative export. Notably the
// kubernetes.io/metadata.name label is server-applied (added by the
// NamespaceDefaultLabelName admission plugin) and is not part of an
// operator's intended declaration.
func filterServerLabels(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch k {
		case "kubernetes.io/metadata.name":
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// filterServerAnnotations removes Flux's reconciliation-state annotations
// and other controller-managed annotations that should not be carried in
// a declarative export. Reconciliation state belongs to a cluster's
// runtime, not the desired-state YAML.
func filterServerAnnotations(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		// Flux reconciler tracking annotations
		if hasPrefix(k, "kustomize.toolkit.fluxcd.io/") ||
			hasPrefix(k, "reconcile.fluxcd.io/") ||
			hasPrefix(k, "fluxcd.io/") {
			continue
		}
		// Helm release tracking
		if hasPrefix(k, "meta.helm.sh/") {
			continue
		}
		// Server-side apply field manager metadata
		if k == "kubectl.kubernetes.io/last-applied-configuration" {
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
