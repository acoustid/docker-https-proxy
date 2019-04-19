# HTTP/HTTPS proxy for Docker

This repository contains a Docker image for configuring and running HAProxy with HTTPS frontend.
SSL certificates are provided by Let's Encrypt. They are generated from a central place and
distributed to all HAProxy instances.

## Example docker-compose.yml file for Docker Swarm

```#!yaml
services:

  letsencrypt:
    image: quay.io/acoustid/https-proxy:latest
    networks:
      - letsencrypt
    volumes:
      - /srv/letsencrypt:/etc/letsencrypt
    environment:
      RUN_LETSENCRYPT_SERVER: 1
      LETSENCRYPT_EMAIL: <your email address>
    deploy:
      endpoint_mode: dnsrr
      placement:
        constraints: [node.labels.letsencrypt == true]
      update_config:
        failure_action: rollback

  proxy:
    image: quay.io/acoustid/https-proxy:latest
    ports:
      - target: 80
        published: 80
        protocol: tcp
        mode: host
      - target: 443
        published: 443
        protocol: tcp
        mode: host
    environment:
      PROXY_LETSENCRYPT_SERVER_HOST: letsencrypt
      PROXY_HTTP_LOG: on
    configs:
      - source: site_xxx
        target: /etc/http-proxy/sites/xxx.json
    networks:
      - proxy
      - letsencrypt
    deploy:
      mode: global
      placement:
        constraints: [node.labels.proxy == true]
      update_config:
        failure_action: rollback
        monitor: 10s
        delay: 30s
```

## Example site declaration

```#!json
{
  "name": "myweb",
  "domain": "example.com",
  "backends": [
    {
      "name": "web",
      "servers": [
        {
          "host": "web-server-1",
          "port": 8080
        }
      ]
    },
    {
      "name": "api",
      "servers": [
        {
          "host": "api-server-1",
          "port": 8080
        },
        {
          "host": "api-server-2",
          "port": 8080
        }
      ]
    }
  ],
  "routes": [
    {
      "path": "/api",
      "backend": "api"
    },
    {
      "path": "/",
      "backend": "web"
    }
  ]
}
```

## Building

    VERSION=$(date +%Y.%m.%d).1
    docker build -t quay.io/acoustid/https-proxy:$VERSION .
    docker push quay.io/acoustid/https-proxy:$VERSION
