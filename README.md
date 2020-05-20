# prometheus-vmware-exporter

Collect metrics ESXi Host

## Build

```sh
docker build -t prometheus-vmware-exporter .
```

## Run

```sh
sudo docker run -d -p 9512:9512 \
  --restart=always \
  --name=prometheus-vmware-exporter \
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
