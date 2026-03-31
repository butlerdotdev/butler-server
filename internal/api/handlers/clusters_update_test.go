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
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestValidateVersionUpgrade(t *testing.T) {
	tests := []struct {
		name    string
		current string
		target  string
		wantErr bool
	}{
		{name: "same version", current: "v1.31.0", target: "v1.31.0", wantErr: false},
		{name: "minor upgrade", current: "v1.31.0", target: "v1.32.0", wantErr: false},
		{name: "patch upgrade", current: "v1.31.0", target: "v1.31.1", wantErr: false},
		{name: "major upgrade", current: "v1.31.0", target: "v2.0.0", wantErr: false},
		{name: "minor downgrade", current: "v1.31.0", target: "v1.30.0", wantErr: true},
		{name: "patch downgrade", current: "v1.31.2", target: "v1.31.1", wantErr: true},
		{name: "major downgrade", current: "v2.0.0", target: "v1.31.0", wantErr: true},
		{name: "empty current", current: "", target: "v1.32.0", wantErr: false},
		{name: "empty target", current: "v1.31.0", target: "", wantErr: false},
		{name: "invalid current", current: "invalid", target: "v1.32.0", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVersionUpgrade(tt.current, tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateVersionUpgrade(%q, %q) error = %v, wantErr %v", tt.current, tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input string
		want  []int
	}{
		{input: "v1.31.0", want: []int{1, 31, 0}},
		{input: "v2.0.0", want: []int{2, 0, 0}},
		{input: "1.31.0", want: []int{1, 31, 0}},
		{input: "invalid", want: nil},
		{input: "v1.31", want: nil},
		{input: "v1.31.0-rc1", want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseVersion(tt.input)
			if tt.want == nil {
				if got != nil {
					t.Errorf("parseVersion(%q) = %v, want nil", tt.input, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseVersion(%q) = nil, want %v", tt.input, tt.want)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseVersion(%q)[%d] = %d, want %d", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestValidateUpdateRequest(t *testing.T) {
	h := &ClusterHandler{}

	makeCluster := func(version string, cpReplicas int64) *unstructured.Unstructured {
		obj := &unstructured.Unstructured{Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"kubernetesVersion": version,
				"controlPlane": map[string]interface{}{
					"replicas": cpReplicas,
				},
				"workers": map[string]interface{}{
					"replicas": int64(3),
				},
			},
		}}
		return obj
	}

	int32Ptr := func(v int32) *int32 { return &v }

	tests := []struct {
		name       string
		cluster    *unstructured.Unstructured
		req        *UpdateRequest
		wantErrors int
	}{
		{
			name:    "valid version upgrade",
			cluster: makeCluster("v1.31.0", 3),
			req: &UpdateRequest{
				ResourceVersion:   "12345",
				KubernetesVersion: strPtr("v1.32.0"),
			},
			wantErrors: 0,
		},
		{
			name:    "version downgrade rejected",
			cluster: makeCluster("v1.31.0", 3),
			req: &UpdateRequest{
				ResourceVersion:   "12345",
				KubernetesVersion: strPtr("v1.30.2"),
			},
			wantErrors: 1,
		},
		{
			name:    "CP replicas must be odd",
			cluster: makeCluster("v1.31.0", 3),
			req: &UpdateRequest{
				ResourceVersion: "12345",
				ControlPlane:    &UpdateControlPlane{Replicas: int32Ptr(2)},
			},
			wantErrors: 1,
		},
		{
			name:    "CP replicas 0 rejected",
			cluster: makeCluster("v1.31.0", 3),
			req: &UpdateRequest{
				ResourceVersion: "12345",
				ControlPlane:    &UpdateControlPlane{Replicas: int32Ptr(0)},
			},
			wantErrors: 1,
		},
		{
			name:    "CP 3 to 1 without ack rejected",
			cluster: makeCluster("v1.31.0", 3),
			req: &UpdateRequest{
				ResourceVersion: "12345",
				ControlPlane:    &UpdateControlPlane{Replicas: int32Ptr(1)},
			},
			wantErrors: 1,
		},
		{
			name:    "CP 3 to 1 with ack accepted",
			cluster: makeCluster("v1.31.0", 3),
			req: &UpdateRequest{
				ResourceVersion:      "12345",
				ControlPlane:         &UpdateControlPlane{Replicas: int32Ptr(1)},
				AcknowledgeDowngrade: true,
			},
			wantErrors: 0,
		},
		{
			name:    "negative worker CPU rejected",
			cluster: makeCluster("v1.31.0", 3),
			req: &UpdateRequest{
				ResourceVersion: "12345",
				Workers: &UpdateWorkers{
					MachineTemplate: map[string]interface{}{"cpu": float64(-1)},
				},
			},
			wantErrors: 1,
		},
		{
			name:    "valid worker replicas",
			cluster: makeCluster("v1.31.0", 3),
			req: &UpdateRequest{
				ResourceVersion: "12345",
				Workers:         &UpdateWorkers{Replicas: int32Ptr(5)},
			},
			wantErrors: 0,
		},
		{
			name:    "worker replicas 0 rejected",
			cluster: makeCluster("v1.31.0", 3),
			req: &UpdateRequest{
				ResourceVersion: "12345",
				Workers:         &UpdateWorkers{Replicas: int32Ptr(0)},
			},
			wantErrors: 1,
		},
		{
			name:    "worker replicas 101 rejected",
			cluster: makeCluster("v1.31.0", 3),
			req: &UpdateRequest{
				ResourceVersion: "12345",
				Workers:         &UpdateWorkers{Replicas: int32Ptr(101)},
			},
			wantErrors: 1,
		},
		{
			name:    "multiple errors at once",
			cluster: makeCluster("v1.31.0", 3),
			req: &UpdateRequest{
				ResourceVersion:   "12345",
				KubernetesVersion: strPtr("v1.30.0"),
				ControlPlane:      &UpdateControlPlane{Replicas: int32Ptr(4)},
				Workers:           &UpdateWorkers{Replicas: int32Ptr(0)},
			},
			wantErrors: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := h.validateUpdateRequest(tt.cluster, tt.req)
			if len(errs) != tt.wantErrors {
				t.Errorf("validateUpdateRequest() returned %d errors, want %d: %+v", len(errs), tt.wantErrors, errs)
			}
		})
	}
}

func TestApplyUpdateRequest(t *testing.T) {
	h := &ClusterHandler{}

	int32Ptr := func(v int32) *int32 { return &v }

	t.Run("partial update only changes specified fields", func(t *testing.T) {
		cluster := &unstructured.Unstructured{Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"kubernetesVersion": "v1.31.0",
				"controlPlane": map[string]interface{}{
					"replicas": int64(3),
				},
				"workers": map[string]interface{}{
					"replicas": int64(3),
					"machineTemplate": map[string]interface{}{
						"cpu":    int64(4),
						"memory": "16Gi",
					},
				},
			},
		}}

		req := &UpdateRequest{
			Workers: &UpdateWorkers{
				MachineTemplate: map[string]interface{}{"cpu": float64(8)},
			},
		}

		h.applyUpdateRequest(cluster, req)

		version, _, _ := unstructured.NestedString(cluster.Object, "spec", "kubernetesVersion")
		if version != "v1.31.0" {
			t.Errorf("kubernetesVersion changed unexpectedly: got %q", version)
		}

		cpReplicas, _, _ := unstructured.NestedInt64(cluster.Object, "spec", "controlPlane", "replicas")
		if cpReplicas != 3 {
			t.Errorf("controlPlane.replicas changed unexpectedly: got %d", cpReplicas)
		}

		workerReplicas, _, _ := unstructured.NestedInt64(cluster.Object, "spec", "workers", "replicas")
		if workerReplicas != 3 {
			t.Errorf("workers.replicas changed unexpectedly: got %d", workerReplicas)
		}

		cpu, _, _ := unstructured.NestedFieldNoCopy(cluster.Object, "spec", "workers", "machineTemplate", "cpu")
		if cpu != float64(8) {
			t.Errorf("workers.machineTemplate.cpu = %v, want 8", cpu)
		}

		mem, _, _ := unstructured.NestedString(cluster.Object, "spec", "workers", "machineTemplate", "memory")
		if mem != "16Gi" {
			t.Errorf("workers.machineTemplate.memory changed unexpectedly: got %q", mem)
		}
	})

	t.Run("version and CP replicas update", func(t *testing.T) {
		cluster := &unstructured.Unstructured{Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"kubernetesVersion": "v1.31.0",
				"controlPlane": map[string]interface{}{
					"replicas": int64(1),
				},
			},
		}}

		req := &UpdateRequest{
			KubernetesVersion: strPtr("v1.32.0"),
			ControlPlane:      &UpdateControlPlane{Replicas: int32Ptr(3)},
		}

		h.applyUpdateRequest(cluster, req)

		version, _, _ := unstructured.NestedString(cluster.Object, "spec", "kubernetesVersion")
		if version != "v1.32.0" {
			t.Errorf("kubernetesVersion = %q, want v1.32.0", version)
		}

		replicas, _, _ := unstructured.NestedInt64(cluster.Object, "spec", "controlPlane", "replicas")
		if replicas != 3 {
			t.Errorf("controlPlane.replicas = %d, want 3", replicas)
		}
	})
}

func strPtr(s string) *string { return &s }
