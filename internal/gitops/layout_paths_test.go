/*
Copyright 2026 The Butler Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package gitops

import "testing"

func TestClassifyUnmatchedRelease(t *testing.T) {
	cases := []struct {
		name             string
		ns               string
		chartInstallsCRDs bool
		want             string
	}{
		// Namespace heuristic (ADR-016 D-A.1): well-known controller
		// namespaces → infrastructure even when chart doesn't install CRDs.
		{"flux-system, no CRDs", "flux-system", false, TierInfrastructure},
		{"cert-manager, no CRDs", "cert-manager", false, TierInfrastructure},
		{"longhorn-system, no CRDs", "longhorn-system", false, TierInfrastructure},
		{"metallb-system, no CRDs", "metallb-system", false, TierInfrastructure},
		{"butler-system, no CRDs", "butler-system", false, TierInfrastructure},
		{"steward-system, no CRDs", "steward-system", false, TierInfrastructure},
		{"kube-system, no CRDs", "kube-system", false, TierInfrastructure},
		{"traefik, no CRDs", "traefik", false, TierInfrastructure},
		// Chart-CRD signal (ADR-017 D2): infrastructure regardless of
		// namespace when chart bundles CRDs. Tenant operators land here.
		{"observability ns, chart installs CRDs (kube-prometheus-stack case)", "observability", true, TierInfrastructure},
		{"strimzi-system ns, chart installs CRDs", "strimzi-system", true, TierInfrastructure},
		{"keda-system ns, chart installs CRDs", "keda-system", true, TierInfrastructure},
		// Apps fallback: not in heuristic, no CRDs.
		{"observability-engineering ns, no CRDs", "observability-engineering", false, TierApps},
		{"my-team ns, no CRDs", "my-team", false, TierApps},
		{"empty ns, no CRDs", "", false, TierApps},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rel := &DiscoveredRelease{
				Namespace:         c.ns,
				ChartInstallsCRDs: c.chartInstallsCRDs,
			}
			if got := classifyUnmatchedRelease(rel); got != c.want {
				t.Errorf("classifyUnmatchedRelease(ns=%q, installsCRDs=%v) = %q, want %q", c.ns, c.chartInstallsCRDs, got, c.want)
			}
		})
	}
}

func TestClassifyUnmatchedRelease_NilSafe(t *testing.T) {
	if got := classifyUnmatchedRelease(nil); got != TierApps {
		t.Errorf("classifyUnmatchedRelease(nil) = %q, want %q", got, TierApps)
	}
}

// TestPathForNative exercises the unified placement rule (D4 corrected):
//   - Namespace → apps/<env>/<name>-namespace.yaml (one ratified flat
//     special-case)
//   - Cluster-scoped → infrastructure/configs/<group-short>/<kind-lower>-<name>.yaml
//   - Namespaced in infra namespace → infrastructure/configs/<group-short>/<kind-lower>-<ns>-<name>.yaml
//   - Everything else → apps/<env>/<group-short>/<kind-lower>-<ns>-<name>.yaml
func TestPathForNative(t *testing.T) {
	cases := []struct {
		name         string
		kind         string
		apiVersion   string
		objName      string
		objNS        string
		isNamespaced bool
		env          string
		wantPath     string
	}{
		// Namespace special-case (flat path) — the one ratified kind exception.
		{"Namespace flat", "Namespace", "v1", "kafka", "", false, "prd", "apps/prd/kafka-namespace.yaml"},
		{"Namespace flat dev env", "Namespace", "v1", "perftest", "", false, "dev", "apps/dev/perftest-namespace.yaml"},

		// Cluster-scoped → infra tier. Filename: <kind-lower>-<name>.yaml.
		// Group-short via TLD-strip: apiextensions.k8s.io → k8s.
		{"CRD cluster-scoped", "CustomResourceDefinition", "apiextensions.k8s.io/v1",
			"kafkas.kafka.strimzi.io", "", false, "prd",
			"infrastructure/configs/apiextensions/customresourcedefinition-kafkas.kafka.strimzi.io.yaml"},
		// rbac.authorization.k8s.io → k8s (last non-TLD segment).
		{"ClusterRole cluster-scoped", "ClusterRole", "rbac.authorization.k8s.io/v1",
			"capi-steward-manager-role", "", false, "prd",
			"infrastructure/configs/rbac/clusterrole-capi-steward-manager-role.yaml"},
		// storage.k8s.io → k8s.
		{"StorageClass cluster-scoped", "StorageClass", "storage.k8s.io/v1",
			"longhorn-rf1", "", false, "prd",
			"infrastructure/configs/storage/storageclass-longhorn-rf1.yaml"},
		// cert-manager.io → cert-manager.
		{"ClusterIssuer cluster-scoped", "ClusterIssuer", "cert-manager.io/v1",
			"butler-internal-ca", "", false, "prd",
			"infrastructure/configs/cert-manager/clusterissuer-butler-internal-ca.yaml"},

		// Namespaced in known infra namespace → infra tier with namespaced filename.
		// Group-short for bitnami.com → bitnami.
		{"SealedSecret in butler-system (infra ns)", "SealedSecret", "bitnami.com/v1alpha1",
			"entra-oidc", "butler-system", true, "prd",
			"infrastructure/configs/bitnami/sealedsecret-butler-system-entra-oidc.yaml"},
		// Deployment in flux-system (infra ns) → infra. apps group has no
		// TLD; group-short = "apps".
		{"Deployment in flux-system (infra ns)", "Deployment", "apps/v1",
			"flux-controller", "flux-system", true, "prd",
			"infrastructure/configs/apps/deployment-flux-system-flux-controller.yaml"},

		// Namespaced in non-infra namespace → app tier. Workload CRs.
		// kafka.strimzi.io → strimzi.
		{"Kafka CR in user ns", "Kafka", "kafka.strimzi.io/v1",
			"pipeline-kafka", "kafka", true, "prd",
			"apps/prd/strimzi/kafka-kafka-pipeline-kafka.yaml"},
		{"KafkaTopic", "KafkaTopic", "kafka.strimzi.io/v1",
			"pipeline-traces", "kafka", true, "prd",
			"apps/prd/strimzi/kafkatopic-kafka-pipeline-traces.yaml"},
		{"KafkaUser", "KafkaUser", "kafka.strimzi.io/v1",
			"vector-consumer", "kafka", true, "prd",
			"apps/prd/strimzi/kafkauser-kafka-vector-consumer.yaml"},
		// keda.sh → keda.
		{"ScaledObject", "ScaledObject", "keda.sh/v1alpha1",
			"vector", "vector", true, "prd",
			"apps/prd/keda/scaledobject-vector-vector.yaml"},

		// butler.butlerlabs.dev → butlerlabs.
		{"Team (cluster-scoped butler CRD)", "Team", "butler.butlerlabs.dev/v1alpha1",
			"platform-engineering", "", false, "prd",
			"infrastructure/configs/butlerlabs/team-platform-engineering.yaml"},

		// User CRD in user namespace — apps tier, group-short via TLD-strip.
		// example.com → example.
		{"unknown user CRD instance", "MyWorkload", "example.com/v1",
			"my-app", "team-payments", true, "prd",
			"apps/prd/example/myworkload-team-payments-my-app.yaml"},

		// nil safety — returns empty.
		{"nil", "", "", "", "", false, "prd", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var n *DiscoveredNative
			if c.kind != "" {
				n = &DiscoveredNative{
					Kind:         c.kind,
					APIVersion:   c.apiVersion,
					Name:         c.objName,
					Namespace:    c.objNS,
					IsNamespaced: c.isNamespaced,
				}
			}
			got := PathForNative(n, c.env)
			if got != c.wantPath {
				t.Errorf("PathForNative(%s/%s) = %q, want %q", c.kind, c.objName, got, c.wantPath)
			}
		})
	}
}

// TestGroupShortFromAPIVersion exercises the three-class derivation:
//   - empty/core (v1)        → "core" sentinel (caller emits flat)
//   - *.k8s.io family        → FIRST segment (k8s machinery grouped by purpose)
//   - operator/vendor groups → last segment before TLD
func TestGroupShortFromAPIVersion(t *testing.T) {
	cases := []struct {
		apiVersion string
		want       string
	}{
		// Class 1: bare-v1 / core — sentinel for flat emission.
		{"", "core"},
		{"v1", "core"},

		// Class 2: .k8s.io family — first segment (purpose grouping).
		{"storage.k8s.io/v1", "storage"},
		{"apiextensions.k8s.io/v1", "apiextensions"},
		{"rbac.authorization.k8s.io/v1", "rbac"},
		{"networking.k8s.io/v1", "networking"},
		{"discovery.k8s.io/v1", "discovery"},
		{"node.k8s.io/v1", "node"},

		// Class 3: operator/vendor groups — last-before-TLD (operator name).
		{"apps/v1", "apps"},
		{"batch/v1", "batch"},
		{"kafka.strimzi.io/v1", "strimzi"},
		{"keda.sh/v1alpha1", "keda"},
		{"cert-manager.io/v1", "cert-manager"},
		{"acme.cert-manager.io/v1", "cert-manager"},
		{"butler.butlerlabs.dev/v1alpha1", "butlerlabs"},
		{"bitnami.com/v1alpha1", "bitnami"},
	}
	for _, c := range cases {
		t.Run(c.apiVersion, func(t *testing.T) {
			if got := groupShortFromAPIVersion(c.apiVersion); got != c.want {
				t.Errorf("groupShortFromAPIVersion(%q) = %q, want %q", c.apiVersion, got, c.want)
			}
		})
	}
}
