FROM golang:1.11 as builder
WORKDIR /go/src/github.com/acoustid/docker-nginx-letsencrypt-proxy/
COPY ./ ./
RUN go build ./cmd/docker_nginx_proxy

FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install -y nginx dumb-init software-properties-common ssl-cert && \
    add-apt-repository ppa:certbot/certbot && \
    apt-get update && \
    apt-get install -y certbot && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log && \
    mkdir /etc/nginx/sites

COPY --from=builder /go/src/github.com/acoustid/docker-nginx-letsencrypt-proxy/docker_nginx_proxy /usr/local/bin/

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["docker_nginx_proxy"]
