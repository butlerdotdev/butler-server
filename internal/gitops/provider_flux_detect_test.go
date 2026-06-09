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
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func fluxNamespace() *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "flux-system"}}
}

func fluxDeployment(name string, readyReplicas int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "flux-system"},
		Status:     appsv1.DeploymentStatus{ReadyReplicas: readyReplicas},
	}
}

// TestDetectFluxStatus covers the detection contract, including the empty
// flux-system namespace that previously false-positived as healthy.
func TestDetectFluxStatus(t *testing.T) {
	tests := []struct {
		name          string
		objects       []runtime.Object
		wantInstalled bool
		wantReady     bool
	}{
		{
			// The e2e-talos fixture: namespace lingers with no controllers.
			// Must report not-installed, not healthy.
			name:          "empty flux-system namespace",
			objects:       []runtime.Object{fluxNamespace()},
			wantInstalled: false,
			wantReady:     false,
		},
		{
			name:          "no flux-system namespace",
			objects:       nil,
			wantInstalled: false,
			wantReady:     false,
		},
		{
			name: "fully installed and ready",
			objects: []runtime.Object{
				fluxNamespace(),
				fluxDeployment("source-controller", 1),
				fluxDeployment("kustomize-controller", 1),
				fluxDeployment("helm-controller", 1),
				fluxDeployment("notification-controller", 1),
			},
			wantInstalled: true,
			wantReady:     true,
		},
		{
			// Installed must not collapse into not-installed when a component
			// is merely unhealthy.
			name: "installed but not all ready",
			objects: []runtime.Object{
				fluxNamespace(),
				fluxDeployment("source-controller", 1),
				fluxDeployment("kustomize-controller", 0),
			},
			wantInstalled: true,
			wantReady:     false,
		},
		{
			// A stray non-Flux deployment in flux-system is not a Flux install.
			name: "namespace with only a non-flux deployment",
			objects: []runtime.Object{
				fluxNamespace(),
				fluxDeployment("some-other-app", 1),
			},
			wantInstalled: false,
			wantReady:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset(tt.objects...)
			status, err := detectFluxStatus(context.Background(), clientset)
			if err != nil {
				t.Fatalf("detectFluxStatus returned error: %v", err)
			}
			if status.Installed != tt.wantInstalled {
				t.Errorf("Installed = %v, want %v (message: %q)", status.Installed, tt.wantInstalled, status.Message)
			}
			if status.Ready != tt.wantReady {
				t.Errorf("Ready = %v, want %v (message: %q)", status.Ready, tt.wantReady, status.Message)
			}
		})
	}
}
