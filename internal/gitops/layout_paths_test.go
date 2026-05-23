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
		ns   string
		want string
	}{
		{"flux-system", TierInfrastructure},
		{"cert-manager", TierInfrastructure},
		{"longhorn-system", TierInfrastructure},
		{"metallb-system", TierInfrastructure},
		{"butler-system", TierInfrastructure},
		{"steward-system", TierInfrastructure},
		{"kube-system", TierInfrastructure},
		{"traefik", TierInfrastructure},
		{"observability-engineering", TierApps},
		{"my-team", TierApps},
		{"", TierApps},
	}
	for _, c := range cases {
		if got := classifyUnmatchedRelease(c.ns); got != c.want {
			t.Errorf("classifyUnmatchedRelease(%q) = %q, want %q", c.ns, got, c.want)
		}
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
		{"StewardControlPlane", "StewardControlPlane", "main", "steward-system", "prd", "infrastructure/configs/steward/main.yaml"},
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
