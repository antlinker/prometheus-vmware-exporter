package collector

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var hosts sync.Map

// Get 查询虚拟机的指标
func Get(opts *Options, logger *log.Logger) (*VMMetrics, error) {
	if err := opts.Valid(); err != nil {
		return nil, err
	}
	mac := opts.mac()
	v, ok := hosts.Load(mac)
	if ok {
		return v.(*VMMetrics), nil
	}
	vm := NewVMMetrics(opts)
	hosts.Store(mac, vm)
	return vm, nil
}

// StartGC 每两分钟清理一次长时间没有抓取的任务
func StartGC(ctx context.Context, idleTimeout time.Duration, logger *log.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Minute):
			clean(idleTimeout, logger)
		}
	}
}

// clean 清理长时间没有抓取的任务
func clean(idleTimeout time.Duration, logger *log.Logger) {
	keys := make([]interface{}, 0, 10)
	hosts.Range(func(k, v interface{}) bool {
		_, ok := k.(string)
		if !ok {
			keys = append(keys, k)
			return true
		}
		vm, ok := v.(*VMMetrics)
		if !ok {
			keys = append(keys, k)
			return true
		}
		if time.Since(vm.last) > idleTimeout {
			keys = append(keys, k)
		}
		return true
	})
	for _, key := range keys {
		outputLogger(logger, "info", "delete metrics of %s", key)
		hosts.Delete(key)
	}
}
