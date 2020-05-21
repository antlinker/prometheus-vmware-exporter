# prometheus-vmware-exporter

Collect metrics ESXi Host

## Help

```
Usage of prometheus-vmware-exporter:
  -idle_timeout int
        The host is requested beyond the specified idle seconds will be deleted, the default value can be overridden by ESX_IDLE_TIMEOUT (default 7200)
  -listen string
        Listen port,the default value can be overridden by ESX_LISTEN (default ":9512")
  -log string
        Log level must be debug or info, the default value can be overridden by ESX_LOG (default "info")
  -password string
        The default password if not provided in the request,the default value can be overridden by ESX_PASSWORD
  -timeout int
        The seconds for request timeout, the default value can be overridden by ESX_TIMEOUT (default 5)
  -username string
        The default username if not provided in the request, the default value can be overridden by ESX_USERNAME
```

## Build

```sh
docker build -t prometheus-vmware-exporter .
```

## Run

```sh
sudo docker run -d -p 9512:9512 \
  --restart=always \
  --name=prometheus-vmware-exporter \
  --env=ESX_USERNAME=USERNAME \
  --env=ESX_PASSWORD=PASSWORD \
  --env=ESX_TIMEOUT=5 \
  --env=ESX_IDLE_TIMEOUT=7200 \
  --env=ESX_LOG=debug \
  prometheus-vmware-exporter

```

## Request

```sh
curl 'http://localhost:9512/vm?host=192.168.1.2&username=root&password=123456&timeout=5' \
  -H 'Cache-Control: no-cache'
```
