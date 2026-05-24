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

func TestPathForNative(t *testing.T) {
	cases := []struct {
		name      string
		kind      string
		objName   string
		objNS     string
		env       string
		wantPath  string
	}{
		{"IdentityProvider", "IdentityProvider", "microsoft-entra", "", "prd", "infrastructure/configs/identity-providers/microsoft-entra.yaml"},
		{"NetworkPool", "NetworkPool", "underlay", "", "prd", "infrastructure/configs/network-pools/underlay.yaml"},
		{"ProviderConfig", "ProviderConfig", "nutanix", "", "prd", "infrastructure/configs/provider-configs/nutanix.yaml"},
		{"ClusterCreationPolicy", "ClusterCreationPolicy", "platform-wide", "", "prd", "infrastructure/configs/cluster-creation-policies/platform-wide.yaml"},
		{"IPAddressPool", "IPAddressPool", "pool-a", "metallb-system", "prd", "infrastructure/configs/metallb/pool-a.yaml"},
		{"L2Advertisement", "L2Advertisement", "adv-a", "metallb-system", "prd", "infrastructure/configs/metallb/adv-a.yaml"},
		{"SealedSecret with namespace prefix", "SealedSecret", "entra-oidc", "butler-system", "prd", "infrastructure/configs/sealed-secrets/butler-system-entra-oidc.yaml"},
		{"gitops ConfigMap", "ConfigMap", "butler-gitops-config", "butler-system", "prd", "infrastructure/configs/butler-gitops-config.yaml"},
		{"other ConfigMap returns empty", "ConfigMap", "other-cm", "butler-system", "prd", ""},
		{"StewardControlPlane explicitly dropped (runtime, butler-controller owned)", "StewardControlPlane", "main", "steward-system", "prd", ""},
		{"Team in apps env", "Team", "platform-engineering", "", "prd", "apps/prd/teams/platform-engineering.yaml"},
		{"Team in apps env dev", "Team", "obs", "", "dev", "apps/dev/teams/obs.yaml"},
		{"unknown kind returns empty", "Pod", "p", "default", "prd", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := &DiscoveredNative{Kind: c.kind, Name: c.objName, Namespace: c.objNS}
			got := PathForNative(n, c.env)
			if got != c.wantPath {
				t.Errorf("PathForNative(%s/%s) = %q, want %q", c.kind, c.objName, got, c.wantPath)
			}
		})
	}
}
