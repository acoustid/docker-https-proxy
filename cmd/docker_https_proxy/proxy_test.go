package main

import (
	"github.com/andreyvit/diff"
	"strings"
	"testing"
)

func TestRenderTemplate(t *testing.T) {
	proxy := NewProxyServer()
	proxy.Sites = append(proxy.Sites, &siteInfo{
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
	})
	proxy.Sites = append(proxy.Sites, &siteInfo{
		Name:   "example2",
		Domain: "example2.com",
		SSL: sslCertInfo{
			CertificatePath: "/etc/ssl/example2.pem",
			PrivateKeyPath:  "/etc/ssl/private/example2.key",
		},
		Backends: []siteBackendInfo{
			{
				Name: "default",
				Servers: []siteBackendServerInfo{
					{
						Host: "srv1.example2.com",
						Port: 8090,
					},
				},
				HealthCheck: siteBackendHealthCheckInfo{
					Path: "/_health",
				},
			},
		},
		Routes: []siteRouteInfo{
			{
				Path:    "/",
				Backend: "default",
			},
		},
	})
	var builder strings.Builder
	err := proxy.haproxyConfigTmpl.Execute(&builder, proxy)
	if err != nil {
		t.Errorf("renderSiteTemplate failed: %v", err)
	}
	output := builder.String()
	expectedOutput := `
resolver 127.0.0.11;

upstream letsencrypt_master {
	server localhost:12812;
}



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
		proxy_pass http://letsencrypt_master;
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
		proxy_pass http://letsencrypt_master;
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


upstream example2_backend_default {
	server srv1.example2.com:8090;
}

server {
	listen 80;
	listen [::]:80;

	server_name example2.com;

	location /.well-known/acme-challenge {
		proxy_pass http://letsencrypt_master;
	}

	location / {
		return 302 https://$host$request_uri;
	}
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;

	server_name example2.com;

	ssl_certificate /etc/ssl/example2.pem;
	ssl_certificate_key /etc/ssl/private/example2.key;

	client_max_body_size 0;

	location /.well-known/acme-challenge {
		proxy_pass http://letsencrypt_master;
	}

	location / {
		proxy_pass http://example2_backend_default;
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
