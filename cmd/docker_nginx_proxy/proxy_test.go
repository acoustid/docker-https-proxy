package main

import (
	"github.com/andreyvit/diff"
	"strings"
	"testing"
)

func TestRenderSiteTemplate(t *testing.T) {
	proxy := NewProxyServer()
	var builder strings.Builder
	site := &siteInfo{
		Name:   "example",
		Domain: "example.com",
		SSL: sslCertInfo{
			CertificatePath: "/etc/ssl/example.pem",
			PrivateKeyPath:  "/etc/ssl/private/example.key",
		},
		Backends: []siteBackendInfo{
			{
				Name: "web",
				Servers: []siteBackendServerInfo{
					{
						Host: "srv1.example.com",
						Port: 8080,
					},
				},
				HealthCheck: siteBackendHealthCheckInfo{
					Path: "/_health",
				},
			},
			{
				Name: "api",
				Servers: []siteBackendServerInfo{
					{
						Host: "srv-api1.example.com",
						Port: 8081,
					},
				},
				HealthCheck: siteBackendHealthCheckInfo{
					Path: "/_health",
				},
			},
		},
		Routes: []siteRouteInfo{
			{
				Path:    "/api",
				Backend: "api",
			},
			{
				Path:    "/",
				Backend: "web",
			},
		},
	}
	err := proxy.renderSiteTemplate(&builder, site)
	if err != nil {
		t.Errorf("renderSiteTemplate failed: %v", err)
	}
	output := builder.String()
	expectedOutput := `
upstream example_backend_web {
	server srv1.example.com:8080;
}

upstream example_backend_api {
	server srv-api1.example.com:8081;
}

server {
	listen 80;
	listen [::]:80;

	server_name example.com;

	location /.well-known/acme-challenge {
		set $example_letsencrypt_server localhost;
		proxy_pass http://$example_letsencrypt_server:12812;
	}

	location / {
		return 302 https://$host$request_uri;
	}
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;

	server_name example.com;

	ssl_certificate /etc/ssl/example.pem;
	ssl_certificate_key /etc/ssl/private/example.key;

	client_max_body_size 0;

	location /.well-known/acme-challenge {
		set $example_letsencrypt_server localhost;
		proxy_pass http://$example_letsencrypt_server:12812;
	}

	location /api {
		proxy_pass http://example_backend_api;
		proxy_set_header Host $http_host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto https;
		proxy_set_header X-Forwarded-Ssl on;
		proxy_read_timeout 3600;
		proxy_connect_timeout 300;
		proxy_redirect off;
		proxy_http_version 1.1;
	}

	location / {
		proxy_pass http://example_backend_web;
		proxy_set_header Host $http_host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto https;
		proxy_set_header X-Forwarded-Ssl on;
		proxy_read_timeout 3600;
		proxy_connect_timeout 300;
		proxy_redirect off;
		proxy_http_version 1.1;
	}
}	
`

	assertLongStringEqual(t, output, expectedOutput)
}

func assertLongStringEqual(t *testing.T, actual string, expected string) {
	if a, e := strings.TrimSpace(actual), strings.TrimSpace(expected); a != e {
		t.Errorf("Result not as expected:\n%v", diff.LineDiff(e, a))
	}
}
