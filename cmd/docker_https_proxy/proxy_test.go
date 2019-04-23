package main

import (
	"github.com/andreyvit/diff"
	"strings"
	"testing"
)

func TestRenderTemplate(t *testing.T) {
	proxy := NewProxyServer()
	proxy.Sites = append(proxy.Sites, &siteInfo{
		Name:       "example",
		Domain:     "example.com",
		AltDomains: []string{"www.example.com"},
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
			},
		},
		Routes: []siteRouteInfo{
			{
				Path:    "/",
				Backend: "default",
			},
		},
	})
	proxy.EnableHTTPLog = true
	var builder strings.Builder
	err := proxy.haproxyConfigTmpl.Execute(&builder, proxy)
	if err != nil {
		t.Errorf("renderSiteTemplate failed: %v", err)
	}
	output := builder.String()
	expectedOutput := `
global
	maxconn 1024
	log stderr format raw daemon notice
	tune.ssl.default-dh-param 2048

defaults
	mode http
	timeout connect 60s
	timeout client 1h
	timeout server 1h
	log stdout format raw daemon
	option httplog

resolvers main
	nameserver dns1 127.0.0.11:53


frontend fe_http
	bind *:80
	acl is_letsencrypt path_beg /.well-known/acme-challenge
	redirect scheme https code 301 if !is_letsencrypt
	use_backend be_letsencrypt if is_letsencrypt

frontend fe_https
	bind *:443 ssl crt /etc/haproxy/ssl/ alpn h2,http/1.1
	acl is_letsencrypt path_beg /.well-known/acme-challenge
	use_backend be_letsencrypt if is_letsencrypt

	acl domain_example ssl_fc_sni -i example.com
	acl alt_domain_example_0 ssl_fc_sni -i www.example.com
	acl route_example_0 path_beg /api
	acl route_example_1 path_beg /
	use_backend be_example_api if domain_example route_example_0
	use_backend be_example_api if alt_domain_example_0 route_example_0
	use_backend be_example_web if domain_example route_example_1
	use_backend be_example_web if alt_domain_example_0 route_example_1

	acl domain_example2 ssl_fc_sni -i example2.com
	acl route_example2_0 path_beg /
	use_backend be_example2_default if domain_example2 route_example2_0


backend be_letsencrypt
	balance roundrobin
	option httpchk GET /_health
	http-check expect status 200
	server-template srv_ 100 localhost:12812 check resolvers main


backend be_example_web
	balance roundrobin
	option httpchk GET /_health
	http-check expect status 200
	server-template srv_0_ 100 srv1.example.com:8080 check resolvers main

backend be_example_api
	balance roundrobin
	option httpchk GET /_health
	http-check expect status 200
	server-template srv_0_ 100 srv-api1.example.com:8081 check resolvers main


backend be_example2_default
	balance roundrobin
	server-template srv_0_ 100 srv1.example2.com:8090 check resolvers main
`

	assertLongStringEqual(t, output, expectedOutput)
}

func assertLongStringEqual(t *testing.T, actual string, expected string) {
	if a, e := strings.TrimSpace(actual), strings.TrimSpace(expected); a != e {
		t.Errorf("Result not as expected:\n%v", diff.LineDiff(e, a))
	}
}
