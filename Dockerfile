FROM golang:1.13.5 as builder
ENV CGO_ENABLED=0
ENV GOPROXY="https://goproxy.cn,https://mirrors.aliyun.com/goproxy/,https://goproxy.io,https://proxy.golang.org,direct"
WORKDIR /prometheus-vmware-exporter
COPY ./ /prometheus-vmware-exporter
RUN CGO_ENABLED=0 GOOS=linux go build -o prometheus-vmware-exporter

FROM alpine:3.8
COPY --from=builder /prometheus-vmware-exporter/prometheus-vmware-exporter /usr/bin/prometheus-vmware-exporter
EXPOSE 9512
ENTRYPOINT ["prometheus-vmware-exporter"]
