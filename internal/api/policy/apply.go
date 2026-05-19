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

// Package policy applies ADR-018 ClusterCreationPolicy curation to
// butler-server's option-list responses. Resolution itself lives in
// butler-api/pkg/policy; this package wraps it with the response-shape
// transformation specific to the four list handlers.
package policy

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	butlerv1alpha1 "github.com/butlerdotdev/butler-api/api/v1alpha1"
	policypkg "github.com/butlerdotdev/butler-api/pkg/policy"
)

// Metadata is the optional `policy` block included in option-list
// responses when a rule applies. butler-console reads this and renders
// the corresponding affordances (badge, pre-select, "curated by policy"
// label). See ADR-018 Decision section 7.
type Metadata struct {
	Name              string   `json:"name"`
	Mode              string   `json:"mode"`
	Values            []string `json:"values,omitempty"`
	Default           string   `json:"default,omitempty"`
	RecommendedReason string   `json:"recommendedReason,omitempty"`
}

// HasID is implemented by the per-option-type response entry types
// (ImageInfo, NetworkInfo, ClusterInfo, StorageContainerInfo) so the
// policy filter can compare against rule values without per-type code.
type HasID interface {
	GetID() string
}

// listGVR is the GVR for ClusterCreationPolicy. Kept local to avoid an
// import cycle with the k8s package.
var listGVR = schema.GroupVersionResource{
	Group:    "butler.butlerlabs.dev",
	Version:  "v1alpha1",
	Resource: "clustercreationpolicies",
}

// ListPolicies fetches all ClusterCreationPolicy resources from the
// cluster. Uses the dynamic client; converts unstructured items into
// typed instances for the resolver.
func ListPolicies(ctx context.Context, dyn dynamic.Interface) ([]butlerv1alpha1.ClusterCreationPolicy, error) {
	ul, err := dyn.Resource(listGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list ClusterCreationPolicy: %w", err)
	}
	out := make([]butlerv1alpha1.ClusterCreationPolicy, 0, len(ul.Items))
	for i := range ul.Items {
		raw, err := json.Marshal(ul.Items[i].Object)
		if err != nil {
			return nil, fmt.Errorf("marshal ClusterCreationPolicy %q: %w", ul.Items[i].GetName(), err)
		}
		var p butlerv1alpha1.ClusterCreationPolicy
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("unmarshal ClusterCreationPolicy %q: %w", ul.Items[i].GetName(), err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Apply runs policy resolution for the given context and option type,
// then filters or reorders the entry slice and returns the filtered
// slice plus optional response metadata.
//
// For pin and allowList modes the entries are filtered to those whose
// ID matches a rule Value. For recommended mode the entries are
// reordered to put recommended IDs first, and metadata is populated so
// the console can badge them. For default mode no filtering happens and
// metadata names the pre-selected ID. When no rule applies, the entries
// pass through unchanged and metadata is nil.
func Apply[T HasID](ctx context.Context, dyn dynamic.Interface, items []T, optType butlerv1alpha1.OptionType, resCtx policypkg.ResolutionContext, policyName *string) ([]T, *Metadata, error) {
	policies, err := ListPolicies(ctx, dyn)
	if err != nil {
		return items, nil, err
	}
	if len(policies) == 0 {
		return items, nil, nil
	}
	rules, sources := policypkg.ResolveWithSources(resCtx, policies)
	rule, ok := rules[optType]
	if !ok {
		return items, nil, nil
	}
	name := sources[optType]
	if policyName != nil {
		*policyName = name
	}

	meta := &Metadata{
		Name:              name,
		Mode:              string(rule.Mode),
		Values:            rule.Values,
		Default:           rule.Default,
		RecommendedReason: rule.RecommendedReason,
	}

	switch rule.Mode {
	case butlerv1alpha1.OptionModePin, butlerv1alpha1.OptionModeAllowList:
		filtered := make([]T, 0, len(items))
		allow := map[string]struct{}{}
		for _, v := range rule.Values {
			allow[v] = struct{}{}
		}
		for _, item := range items {
			if _, in := allow[item.GetID()]; in {
				filtered = append(filtered, item)
			}
		}
		return filtered, meta, nil
	case butlerv1alpha1.OptionModeRecommended:
		recommended := map[string]struct{}{}
		for _, v := range rule.Values {
			recommended[v] = struct{}{}
		}
		head := make([]T, 0, len(rule.Values))
		tail := make([]T, 0, len(items))
		for _, item := range items {
			if _, in := recommended[item.GetID()]; in {
				head = append(head, item)
			} else {
				tail = append(tail, item)
			}
		}
		return append(head, tail...), meta, nil
	case butlerv1alpha1.OptionModeDefault:
		return items, meta, nil
	default:
		return items, nil, nil
	}
}
