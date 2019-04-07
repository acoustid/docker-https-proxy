Building:

    VERSION=$(date +%Y%m%d).1
    docker build -t quay.io/acoustid/nginx-letsencrypt-proxy:$VERSION .
    docker push quay.io/acoustid/nginx-letsencrypt-proxy:$VERSION
