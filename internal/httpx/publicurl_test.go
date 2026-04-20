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

package httpx

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/butlerdotdev/butler-server/internal/config"
)

func TestPublicBaseURL(t *testing.T) {
	const defaultBase = "http://localhost:8080"

	tests := []struct {
		name     string
		frontend string
		base     string
		trust    bool
		host     string
		xfp      string
		xfh      string
		tls      bool
		want     string
	}{
		{
			name: "FrontendURL wins over everything",
			frontend: "https://butler.example.com", base: defaultBase,
			host: "ignored.example.com", want: "https://butler.example.com",
		},
		{
			name: "BaseURL explicit overrides request",
			base: "https://butler.example.com",
			host: "ignored.example.com", want: "https://butler.example.com",
		},
		{
			name:     "FrontendURL beats BaseURL",
			frontend: "https://front.example.com", base: "https://base.example.com",
			host: "ignored.example.com", want: "https://front.example.com",
		},
		{
			name: "BaseURL at default placeholder is treated as unset",
			base: defaultBase,
			host: "butler.example.com", want: "http://butler.example.com",
		},
		{
			name: "TrustProxyHeaders false ignores X-Forwarded-Host",
			base: defaultBase,
			host: "real.example.com", xfp: "https", xfh: "evil.example.com",
			want: "http://real.example.com",
		},
		{
			name:  "TrustProxyHeaders true honors XFP and XFH",
			base:  defaultBase, trust: true,
			host: "real.example.com", xfp: "https", xfh: "butler.example.com",
			want: "https://butler.example.com",
		},
		{
			name:  "TrustProxyHeaders true strips default https port",
			base:  defaultBase, trust: true,
			host: "real.example.com", xfp: "https", xfh: "butler.example.com:443",
			want: "https://butler.example.com",
		},
		{
			name:  "TrustProxyHeaders true strips default http port",
			base:  defaultBase, trust: true,
			host: "real.example.com", xfp: "http", xfh: "butler.example.com:80",
			want: "http://butler.example.com",
		},
		{
			name:  "TrustProxyHeaders true keeps non-default port",
			base:  defaultBase, trust: true,
			host: "real.example.com", xfp: "https", xfh: "butler.example.com:8443",
			want: "https://butler.example.com:8443",
		},
		{
			name:  "TrustProxyHeaders true takes first XFH value",
			base:  defaultBase, trust: true,
			host: "real.example.com", xfp: "https", xfh: "first.example.com, second.example.com",
			want: "https://first.example.com",
		},
		{
			name: "r.TLS non-nil promotes to https",
			base: defaultBase,
			host: "butler.example.com", tls: true,
			want: "https://butler.example.com",
		},
		{
			name:  "r.TLS beats X-Forwarded-Proto=http",
			base:  defaultBase, trust: true,
			host: "butler.example.com", xfp: "http", tls: true,
			want: "https://butler.example.com",
		},
		{
			name: "IPv6 default port stripped and rebracketed",
			base: defaultBase,
			host: "[::1]:443", tls: true,
			want: "https://[::1]",
		},
		{
			name: "IPv6 non-default port preserved",
			base: defaultBase,
			host: "[::1]:8443", tls: true,
			want: "https://[::1]:8443",
		},
		{
			name: "empty Host and no override returns empty",
			base: defaultBase,
			host: "", want: "",
		},
		{
			name:  "invalid X-Forwarded-Proto falls through to http",
			base:  defaultBase, trust: true,
			host: "butler.example.com", xfp: "gopher",
			want: "http://butler.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				FrontendURL: tt.frontend,
				Server: config.ServerConfig{
					BaseURL:           tt.base,
					TrustProxyHeaders: tt.trust,
				},
			}
			r := &http.Request{
				Host:   tt.host,
				Header: http.Header{},
			}
			if tt.xfp != "" {
				r.Header.Set("X-Forwarded-Proto", tt.xfp)
			}
			if tt.xfh != "" {
				r.Header.Set("X-Forwarded-Host", tt.xfh)
			}
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}

			got := PublicBaseURL(r, cfg)
			if got != tt.want {
				t.Errorf("PublicBaseURL: got %q, want %q", got, tt.want)
			}
		})
	}
}
