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
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// fluxControllerNames are the gotk controller Deployments a `flux bootstrap`
// creates in flux-system. Their presence is the signal that the Flux engine is
// installed; the namespace existing on its own is not, since a prior bootstrap
// or uninstall can leave an empty flux-system namespace behind.
var fluxControllerNames = map[string]bool{
	"source-controller":       true,
	"kustomize-controller":    true,
	"helm-controller":         true,
	"notification-controller": true,
}

// FluxEngineStatus is the single source of truth for Flux install/readiness,
// consumed by both FluxProvider.CheckInstalled (the CLI status verb) and
// detectFlux (discover, the export/preview gate, and the console banner).
// Installed and Ready are distinct: a partial install is Installed=true,
// Ready=false.
//
// Installed (not Ready) is what gates export/preview. The export path reads
// Helm release Secrets, native resources, and Flux bootstrap CRs straight from
// the API server and needs no Flux controller actually running, so the engine
// being present is sufficient to export. Ready drives only the healthy vs
// degraded distinction in status and the console banner.
type FluxEngineStatus struct {
	Installed  bool
	Ready      bool
	Version    string
	Components []ComponentStatus
}

// detectFluxEngine reports Flux install/readiness in flux-system. It takes a
// kubernetes.Interface so the detection is unit-testable with a fake clientset.
//
// Installed requires at least one recognized Flux controller Deployment; an
// empty or controller-less flux-system namespace reports not-installed. Ready
// requires every present recognized controller to have a ready replica.
func detectFluxEngine(ctx context.Context, clientset kubernetes.Interface) (FluxEngineStatus, error) {
	var status FluxEngineStatus

	// No explicit flux-system namespace check: listing deployments in an absent
	// namespace returns an empty list, so the controller-count gate below already
	// covers both "namespace absent" and "namespace present but empty" -> not
	// installed. A real LIST error (e.g. RBAC) is surfaced.
	deployments, err := clientset.AppsV1().Deployments("flux-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return status, fmt.Errorf("failed to list flux-system deployments: %w", err)
	}

	allReady := true
	controllers := 0
	status.Components = make([]ComponentStatus, 0, len(deployments.Items))
	for _, deployment := range deployments.Items {
		if !fluxControllerNames[deployment.Name] {
			continue
		}
		controllers++
		ready := deployment.Status.ReadyReplicas > 0
		message := "ready"
		if !ready {
			message = "not ready"
			allReady = false
		}
		status.Components = append(status.Components, ComponentStatus{Name: deployment.Name, Ready: ready, Message: message})
	}

	if controllers == 0 {
		return status, nil
	}

	status.Installed = true
	status.Ready = allReady

	if deployment, err := clientset.AppsV1().Deployments("flux-system").Get(ctx, "source-controller", metav1.GetOptions{}); err == nil && len(deployment.Spec.Template.Spec.Containers) > 0 {
		if parts := strings.Split(deployment.Spec.Template.Spec.Containers[0].Image, ":"); len(parts) > 1 {
			status.Version = parts[len(parts)-1]
		}
	}

	return status, nil
}

// readyComponentNames returns the names of the ready Flux controllers, used for
// the GitOpsEngineStatus.Components "components running" display.
func (s FluxEngineStatus) readyComponentNames() []string {
	names := make([]string, 0, len(s.Components))
	for _, c := range s.Components {
		if c.Ready {
			names = append(names, c.Name)
		}
	}
	return names
}
