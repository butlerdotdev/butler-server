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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// DiscoveredNative represents a single native (non-HelmRelease) Kubernetes
// resource discovered during export. The Object field carries the full
// unstructured manifest so the layout generator can write it verbatim
// after any export-time cleanup (status stripping, server-generated field
// removal).
type DiscoveredNative struct {
	Kind       string
	APIVersion string
	Namespace  string
	Name       string
	Object     *unstructured.Unstructured
}

// NativeDiscoveryResult buckets discovered native resources by kind so the
// layout generator can iterate them with kind-specific placement rules. See
// ADR-016 subsection 1 for the canonical list.
type NativeDiscoveryResult struct {
	IdentityProviders            []*DiscoveredNative
	NetworkPools                 []*DiscoveredNative
	ProviderConfigs              []*DiscoveredNative
	Teams                        []*DiscoveredNative
	ClusterCreationPolicies      []*DiscoveredNative
	ButlerGitOpsConfig           *DiscoveredNative
	SealedSecrets                []*DiscoveredNative
	MetalLBIPAddressPools        []*DiscoveredNative
	MetalLBL2Advertisements      []*DiscoveredNative
	StewardControlPlanes         []*DiscoveredNative
	StewardControlPlaneTemplates []*DiscoveredNative
}

// nativeKind binds a GVR to its discovery target on NativeDiscoveryResult.
// Discovery is read-only: each entry calls List on the dynamic client and
// either appends to the slice or sets the singleton pointer. Missing CRDs
// and RBAC denials are skipped, not fatal.
type nativeKind struct {
	gvr        schema.GroupVersionResource
	namespace  string // empty for cluster-scope or all-namespaces
	apply      func(result *NativeDiscoveryResult, items []*DiscoveredNative)
	singleton  string // when set, the singleton ConfigMap-by-name lookup applies
	applyOne   func(result *NativeDiscoveryResult, item *DiscoveredNative)
}

func nativeKinds() []nativeKind {
	return []nativeKind{
		{
			gvr:   schema.GroupVersionResource{Group: "butler.butlerlabs.dev", Version: "v1alpha1", Resource: "identityproviders"},
			apply: func(r *NativeDiscoveryResult, items []*DiscoveredNative) { r.IdentityProviders = items },
		},
		{
			gvr:   schema.GroupVersionResource{Group: "butler.butlerlabs.dev", Version: "v1alpha1", Resource: "networkpools"},
			apply: func(r *NativeDiscoveryResult, items []*DiscoveredNative) { r.NetworkPools = items },
		},
		{
			gvr:   schema.GroupVersionResource{Group: "butler.butlerlabs.dev", Version: "v1alpha1", Resource: "providerconfigs"},
			apply: func(r *NativeDiscoveryResult, items []*DiscoveredNative) { r.ProviderConfigs = items },
		},
		{
			gvr:   schema.GroupVersionResource{Group: "butler.butlerlabs.dev", Version: "v1alpha1", Resource: "teams"},
			apply: func(r *NativeDiscoveryResult, items []*DiscoveredNative) { r.Teams = items },
		},
		{
			gvr:   schema.GroupVersionResource{Group: "butler.butlerlabs.dev", Version: "v1alpha1", Resource: "clustercreationpolicies"},
			apply: func(r *NativeDiscoveryResult, items []*DiscoveredNative) { r.ClusterCreationPolicies = items },
		},
		{
			gvr:   schema.GroupVersionResource{Group: "bitnami.com", Version: "v1alpha1", Resource: "sealedsecrets"},
			apply: func(r *NativeDiscoveryResult, items []*DiscoveredNative) { r.SealedSecrets = items },
		},
		{
			gvr:       schema.GroupVersionResource{Group: "metallb.io", Version: "v1beta1", Resource: "ipaddresspools"},
			namespace: "metallb-system",
			apply:     func(r *NativeDiscoveryResult, items []*DiscoveredNative) { r.MetalLBIPAddressPools = items },
		},
		{
			gvr:       schema.GroupVersionResource{Group: "metallb.io", Version: "v1beta1", Resource: "l2advertisements"},
			namespace: "metallb-system",
			apply:     func(r *NativeDiscoveryResult, items []*DiscoveredNative) { r.MetalLBL2Advertisements = items },
		},
		{
			gvr:   schema.GroupVersionResource{Group: "controlplane.cluster.x-k8s.io", Version: "v1alpha1", Resource: "stewardcontrolplanes"},
			apply: func(r *NativeDiscoveryResult, items []*DiscoveredNative) { r.StewardControlPlanes = items },
		},
		{
			gvr:   schema.GroupVersionResource{Group: "controlplane.cluster.x-k8s.io", Version: "v1alpha1", Resource: "stewardcontrolplanetemplates"},
			apply: func(r *NativeDiscoveryResult, items []*DiscoveredNative) { r.StewardControlPlaneTemplates = items },
		},
	}
}

// DiscoverNativeResources enumerates the native (non-HelmRelease) resources
// listed in ADR-016 subsection 1. Missing CRDs and RBAC denials are skipped
// per the ADR — a kind not registered on the cluster simply produces an
// empty slice rather than failing the whole export. The butler-gitops-config
// ConfigMap is fetched by name from butler-system.
//
// Read-only: only List and Get are called; no cluster writes.
func DiscoverNativeResources(ctx context.Context, kubeconfig []byte) (*NativeDiscoveryResult, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	result := &NativeDiscoveryResult{}

	for _, k := range nativeKinds() {
		items, err := listNativeKind(ctx, dynClient, k)
		if err != nil {
			slog.Debug("native discovery skipped kind", "gvr", k.gvr.String(), "error", err)
			continue
		}
		k.apply(result, items)
	}

	cm, err := clientset.CoreV1().ConfigMaps("butler-system").Get(ctx, "butler-gitops-config", metav1.GetOptions{})
	if err == nil {
		obj := unstructured.Unstructured{}
		obj.SetAPIVersion("v1")
		obj.SetKind("ConfigMap")
		obj.SetName(cm.Name)
		obj.SetNamespace(cm.Namespace)
		data := make(map[string]interface{}, len(cm.Data))
		for k, v := range cm.Data {
			data[k] = v
		}
		_ = unstructured.SetNestedMap(obj.Object, data, "data")
		result.ButlerGitOpsConfig = &DiscoveredNative{
			Kind:       "ConfigMap",
			APIVersion: "v1",
			Namespace:  cm.Namespace,
			Name:       cm.Name,
			Object:     &obj,
		}
	} else if !apierrors.IsNotFound(err) {
		slog.Debug("native discovery skipped butler-gitops-config", "error", err)
	}

	return result, nil
}

func listNativeKind(ctx context.Context, dynClient dynamic.Interface, k nativeKind) ([]*DiscoveredNative, error) {
	var list *unstructured.UnstructuredList
	var err error
	if k.namespace != "" {
		list, err = dynClient.Resource(k.gvr).Namespace(k.namespace).List(ctx, metav1.ListOptions{})
	} else {
		list, err = dynClient.Resource(k.gvr).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, err
	}

	items := make([]*DiscoveredNative, 0, len(list.Items))
	for i := range list.Items {
		obj := list.Items[i].DeepCopy()
		stripServerGeneratedFields(obj)
		items = append(items, &DiscoveredNative{
			Kind:       obj.GetKind(),
			APIVersion: obj.GetAPIVersion(),
			Namespace:  obj.GetNamespace(),
			Name:       obj.GetName(),
			Object:     obj,
		})
	}
	return items, nil
}

// stripServerGeneratedFields removes fields that the API server populates
// (uid, resourceVersion, generation, status, managedFields, creationTimestamp).
// These should not appear in exported manifests — they belong to a specific
// cluster instance, not to the declarative config that the GitOps tree carries.
func stripServerGeneratedFields(obj *unstructured.Unstructured) {
	meta, ok := obj.Object["metadata"].(map[string]interface{})
	if !ok {
		return
	}
	for _, field := range []string{
		"uid",
		"resourceVersion",
		"generation",
		"creationTimestamp",
		"managedFields",
		"selfLink",
	} {
		delete(meta, field)
	}
	delete(obj.Object, "status")
}
