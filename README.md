Example site declaration:

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

Building:

    VERSION=$(date +%Y.%m.%d).1
    docker build -t quay.io/acoustid/https-proxy:$VERSION .
    docker push quay.io/acoustid/https-proxy:$VERSION
