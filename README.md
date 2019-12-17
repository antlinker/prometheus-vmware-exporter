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
  --env=ESX_HOST=192.168.175.50 \
  --env=ESX_USERNAME=root \
  --env=ESX_PASSWORD=abc-123 \
  --env=ESX_LOG=debug \
  pv-exporter 
```