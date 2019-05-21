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
		AllowHTTP: true,
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
		EnableAuth: true,
		Users: []siteUserInfo{
			{
				Name:     "lukas",
				Password: "pass",
			},
			{
				Name:     "lukas2",
				Password: "pass2",
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
	default-server init-addr last,libc,none
	option httplog

resolvers main
	nameserver dns1 127.0.0.11:53

listen stats
  bind *:7932
  mode http
  stats enable
  stats hide-version
  stats realm HAproxy\ Statistics
  stats uri /_stats
  stats auth stats:nopassword




userlist users_example2
  user lukas password pass
  user lukas2 password pass2


frontend fe_proxy
	bind *:80
	bind *:443 ssl crt /etc/haproxy/ssl/ alpn h2,http/1.1

	capture request header Host len 20
	capture response header Content-Length len 10

	acl is_health path_beg /_health
	acl is_letsencrypt path_beg /.well-known/acme-challenge
	use_backend be_utils if is_health
	use_backend be_letsencrypt if is_letsencrypt


	acl domain_example hdr(Host) -i example.com
	acl domain_example_80 hdr(Host) -i example.com:80
	acl domain_example_443 hdr(Host) -i example.com:443
	acl alt_domain_example_0 hdr(Host) -i www.example.com
	acl alt_domain_example_0_80 hdr(Host) -i www.example.com:80
	acl alt_domain_example_0_443 hdr(Host) -i www.example.com:443
	acl route_example_0 path_beg /api
	acl route_example_1 path_beg /
	use_backend be_example_api if domain_example route_example_0
	use_backend be_example_api if domain_example_80 route_example_0
	use_backend be_example_api if domain_example_443 route_example_0
	use_backend be_example_api if alt_domain_example_0 route_example_0
	use_backend be_example_api if alt_domain_example_0_80 route_example_0
	use_backend be_example_api if alt_domain_example_0_443 route_example_0
	use_backend be_example_web if domain_example route_example_1
	use_backend be_example_web if domain_example_80 route_example_1
	use_backend be_example_web if domain_example_443 route_example_1
	use_backend be_example_web if alt_domain_example_0 route_example_1
	use_backend be_example_web if alt_domain_example_0_80 route_example_1
	use_backend be_example_web if alt_domain_example_0_443 route_example_1

	acl domain_example2 hdr(Host) -i example2.com
	acl domain_example2_80 hdr(Host) -i example2.com:80
	acl domain_example2_443 hdr(Host) -i example2.com:443
	acl auth_example2 http_auth(users_example2)
	http-request auth realm private if domain_example2 !auth_example2
	http-request auth realm private if domain_example2_80 !auth_example2
	http-request auth realm private if domain_example2_443 !auth_example2
	acl route_example2_0 path_beg /
	use_backend be_example2_default if domain_example2 route_example2_0 auth_example2
	use_backend be_example2_default if domain_example2_80 route_example2_0 auth_example2
	use_backend be_example2_default if domain_example2_443 route_example2_0 auth_example2


backend be_utils
	balance roundrobin
	server srv 127.0.0.1:12813


backend be_letsencrypt
	balance roundrobin
	option httpchk GET /_health
	http-check expect status 200
	server-template srv_ 100 localhost:12812 check resolvers main


backend be_example_web
	balance roundrobin
	option forwardfor
	http-request set-header X-Forwarded-Host %[req.hdr(Host)]
	http-request set-header X-Forwarded-Port %[dst_port]
	http-request set-header X-Forwarded-Proto https if { ssl_fc }
	option httpchk GET /_health
	http-check expect status 200
	server-template srv_0_ 100 srv1.example.com:8080 check resolvers main
	redirect scheme https code 301 if !{ ssl_fc }

backend be_example_api
	balance roundrobin
	option forwardfor
	http-request set-header X-Forwarded-Host %[req.hdr(Host)]
	http-request set-header X-Forwarded-Port %[dst_port]
	http-request set-header X-Forwarded-Proto https if { ssl_fc }
	option httpchk GET /_health
	http-check expect status 200
	server-template srv_0_ 100 srv-api1.example.com:8081 check resolvers main
	redirect scheme https code 301 if !{ ssl_fc }


backend be_example2_default
	balance roundrobin
	option forwardfor
	http-request set-header X-Forwarded-Host %[req.hdr(Host)]
	http-request set-header X-Forwarded-Port %[dst_port]
	http-request set-header X-Forwarded-Proto https if { ssl_fc }
	http-request del-header Authorization
	server-template srv_0_ 100 srv1.example2.com:8090 check resolvers main
`

	assertLongStringEqual(t, output, expectedOutput)
}

func assertLongStringEqual(t *testing.T, actual string, expected string) {
	if a, e := strings.TrimSpace(actual), strings.TrimSpace(expected); a != e {
		t.Errorf("Result not as expected:\n%v", diff.LineDiff(e, a))
	}
}
