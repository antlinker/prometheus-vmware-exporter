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
