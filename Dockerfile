FROM golang:1.11 as builder
WORKDIR /go/src/github.com/acoustid/docker-https-proxy/
COPY ./ ./
RUN go build ./cmd/docker_https_proxy

FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install -y dumb-init software-properties-common ssl-cert haproxy && \
    add-apt-repository ppa:certbot/certbot && \
    apt-get update && \
    apt-get install -y certbot && \
    mkdir -p /etc/https-proxy/sites

COPY --from=builder /go/src/github.com/acoustid/docker-https-proxy/docker_https_proxy /usr/local/bin/

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["docker_https_proxy"]
