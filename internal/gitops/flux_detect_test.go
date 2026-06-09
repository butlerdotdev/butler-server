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
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// newFluxDynClient builds a fake dynamic client that knows the Flux bootstrap CR
// list kinds enrichFluxFromBootstrapCRs reads, so LIST does not panic. The CRs
// are absent, exercising enrich's graceful empty path (detection is unaffected).
func newFluxDynClient() *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"}:   "GitRepositoryList",
		{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}: "KustomizationList",
	})
}

func fluxNS() *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "flux-system"}}
}

func fluxDep(name string, readyReplicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "flux-system"},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: readyReplicas},
	}
}

func allFourReady() []runtime.Object {
	return []runtime.Object{
		fluxNS(),
		fluxDep("source-controller", 1),
		fluxDep("kustomize-controller", 1),
		fluxDep("helm-controller", 1),
		fluxDep("notification-controller", 1),
	}
}

// TestDetectFluxEngine exercises the shared detector across the install
// spectrum, including the partial window where the old detectors diverged.
func TestDetectFluxEngine(t *testing.T) {
	tests := []struct {
		name          string
		objects       []runtime.Object
		wantInstalled bool
		wantReady     bool
	}{
		{"empty flux-system namespace", []runtime.Object{fluxNS()}, false, false},
		{"no flux-system namespace", nil, false, false},
		{"all controllers ready", allFourReady(), true, true},
		{
			"partial: 1 of 4 ready",
			[]runtime.Object{fluxNS(), fluxDep("source-controller", 1), fluxDep("kustomize-controller", 0), fluxDep("helm-controller", 0), fluxDep("notification-controller", 0)},
			true, false,
		},
		{
			"partial: 3 of 4 ready",
			[]runtime.Object{fluxNS(), fluxDep("source-controller", 1), fluxDep("kustomize-controller", 1), fluxDep("helm-controller", 1), fluxDep("notification-controller", 0)},
			true, false,
		},
		{
			"namespace with only a non-flux deployment",
			[]runtime.Object{fluxNS(), fluxDep("some-other-app", 1)},
			false, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := detectFluxEngine(context.Background(), fake.NewSimpleClientset(tt.objects...))
			if err != nil {
				t.Fatalf("detectFluxEngine error: %v", err)
			}
			if s.Installed != tt.wantInstalled || s.Ready != tt.wantReady {
				t.Errorf("Installed=%v Ready=%v, want Installed=%v Ready=%v", s.Installed, s.Ready, tt.wantInstalled, tt.wantReady)
			}
		})
	}
}

// TestStatusDiscoverAgree is the anti-divergence guarantee: the status side
// (detectFluxEngine, which CheckInstalled wraps) and the discover side
// (detectFlux) report the SAME installed/ready for the same cluster state.
func TestStatusDiscoverAgree(t *testing.T) {
	dyn := newFluxDynClient()
	states := []struct {
		name    string
		objects []runtime.Object
	}{
		{"healthy", allFourReady()},
		{"partial", []runtime.Object{fluxNS(), fluxDep("source-controller", 1), fluxDep("kustomize-controller", 0)}},
		{"empty-ns", []runtime.Object{fluxNS()}},
		{"no-ns", nil},
	}
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(st.objects...)
			engine, err := detectFluxEngine(context.Background(), cs)
			if err != nil {
				t.Fatalf("detectFluxEngine error: %v", err)
			}
			ge := detectFlux(context.Background(), cs, dyn)
			discoverInstalled := ge != nil && ge.Installed
			discoverReady := ge != nil && ge.Ready
			if discoverInstalled != engine.Installed || discoverReady != engine.Ready {
				t.Errorf("discover(installed=%v ready=%v) != status(installed=%v ready=%v)",
					discoverInstalled, discoverReady, engine.Installed, engine.Ready)
			}
		})
	}
}

// TestDetectFluxGate locks in the G3 gate semantics. The export/preview gate is
// `GitOpsEngine == nil || !Installed`, so detectFlux returns non-nil+Installed
// exactly when the engine is present (regardless of readiness).
func TestDetectFluxGate(t *testing.T) {
	dyn := newFluxDynClient()
	ctx := context.Background()
	allowed := func(objs ...runtime.Object) bool {
		ge := detectFlux(ctx, fake.NewSimpleClientset(objs...), dyn)
		return ge != nil && ge.Installed
	}

	// CHANGED -> ALLOWED: a partial install with fewer than 2 ready controllers
	// was blocked under the old >=2-ready gate; under G3 (engine present) it is
	// allowed, because export reads API data and needs no controller running.
	if !allowed(fluxNS(), fluxDep("source-controller", 1), fluxDep("kustomize-controller", 0), fluxDep("helm-controller", 0), fluxDep("notification-controller", 0)) {
		t.Error("partial Flux (1 of 4 ready) must be ALLOWED under G3")
	}

	// CHANGED -> BLOCKED: 2 ready non-Flux deployments passed the old
	// >=2-any-ready gate; under G3 they are not a Flux engine, so blocked.
	if allowed(fluxNS(), fluxDep("other-a", 1), fluxDep("other-b", 1)) {
		t.Error("flux-system with only non-Flux deployments must be BLOCKED under G3")
	}

	// UNCHANGED: empty namespace blocked; healthy allowed.
	if allowed(fluxNS()) {
		t.Error("empty flux-system must be BLOCKED")
	}
	if !allowed(allFourReady()...) {
		t.Error("healthy Flux must be ALLOWED")
	}
}

// TestDetectFluxEngine_ListErrorPropagates proves a genuine deployment LIST
// error (e.g. RBAC) is surfaced, not silently mapped to not-installed. Only an
// absent/empty namespace (an empty list, no error) means not-installed.
func TestDetectFluxEngine_ListErrorPropagates(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "deployments", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("forbidden")
	})
	_, err := detectFluxEngine(context.Background(), cs)
	if err == nil {
		t.Error("expected the LIST error to propagate, not be swallowed as not-installed")
	}
}
