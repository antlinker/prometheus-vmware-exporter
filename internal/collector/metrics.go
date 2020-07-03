package collector

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

// Namespace 命名空间
const Namespace = "vmware"

// createPrometheusHostPowerState 创建电源状态指标
func createPrometheusHostPowerState(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "host",
		Name:      "power_state",
		Help:      "poweredOn 1, poweredOff 2, standBy 3, other 0",
	}, []string{"host_name"})
}

// createPrometheusHostBoot  创建主机启动时间指标
func createPrometheusHostBoot(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "host",
		Name:      "boot_timestamp_seconds",
		Help:      "Uptime host",
	}, []string{"host_name"})
}

// createPrometheusTotalCPU 创建cpu_max指标
func createPrometheusTotalCPU(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "host",
		Name:      "cpu_max",
		Help:      "CPU total",
	}, []string{"host_name"})
}

// createPrometheusUsageCPU 创建cpu_usage指标
func createPrometheusUsageCPU(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "host",
		Name:      "cpu_usage",
		Help:      "CPU Usage",
	}, []string{"host_name"})
}

// createPrometheusTotalMem 创建memory_max指标
func createPrometheusTotalMem(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "host",
		Name:      "memory_max",
		Help:      "Memory max",
	}, []string{"host_name"})
}

// createPrometheusUsageMem 创建memory_usage指标
func createPrometheusUsageMem(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "host",
		Name:      "memory_usage",
		Help:      "Memory Usage",
	}, []string{"host_name"})
}

// createPrometheusDiskOk 创建disk_ok指标
func createPrometheusDiskOk(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "host",
		Name:      "disk_ok",
		Help:      "Disk is working normally",
	}, []string{"host_name", "device"})
}

// createPrometheusTotalDs 创建capacity_size指标
func createPrometheusTotalDs(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "datastore",
		Name:      "capacity_size",
		Help:      "Datastore total",
	}, []string{"ds_name", "host_name"})
}

// createPrometheusUsageDs 创建freespace_size指标
func createPrometheusUsageDs(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "datastore",
		Name:      "freespace_size",
		Help:      "Datastore free",
	}, []string{"ds_name", "host_name"})
}

// createPrometheusVMBoot 创建虚拟机启动时间指标
func createPrometheusVMBoot(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "vm",
		Name:      "boot_timestamp_seconds",
		Help:      "VMWare VM boot time in seconds",
	}, []string{"vm_name", "host_name"})
}

// createPrometheusVMCPUAval 创建vm_cpu_avaleblemhz指标
func createPrometheusVMCPUAval(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "vm",
		Name:      "cpu_avaleblemhz",
		Help:      "VMWare VM usage CPU",
	}, []string{"vm_name", "host_name"})
}

// createprometheusVMCPUUsage 创建vm_cpu_usagemhz指标
func createprometheusVMCPUUsage(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "vm",
		Name:      "cpu_usagemhz",
		Help:      "VMWare VM usage CPU",
	}, []string{"vm_name", "host_name"})
}

// createPrometheusVMNumCPU 创建vm_num_cpu指标
func createPrometheusVMNumCPU(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "vm",
		Name:      "num_cpu",
		Help:      "Available number of cores",
	}, []string{"vm_name", "host_name"})
}

// createPrometheusVMMemAval 创建vm_mem_avaleble指标
func createPrometheusVMMemAval(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "vm",
		Name:      "mem_avaleble",
		Help:      "Available memory",
	}, []string{"vm_name", "host_name"})
}

// createPrometheusVMMemUsage 创建vm_mem_usage指标
func createPrometheusVMMemUsage(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "vm",
		Name:      "mem_usage",
		Help:      "Usage memory",
	}, []string{"vm_name", "host_name"})
}

// createPrometheusVMNetRec 创建vm_net_rec指标
func createPrometheusVMNetRec(factory promauto.Factory) *prometheus.GaugeVec {
	return factory.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Subsystem: "vm",
		Name:      "net_rec",
		Help:      "Usage memory",
	}, []string{"vm_name", "host_name"})
}

// VMMetrics vmware exsi指标
type VMMetrics struct {
	host, port, username, password string

	registry *prometheus.Registry

	prometheusHostPowerState,
	prometheusHostBoot,
	prometheusTotalCPU,
	prometheusUsageCPU,
	prometheusTotalMem,
	prometheusUsageMem,
	prometheusDiskOk,
	prometheusTotalDs,
	prometheusUsageDs,
	prometheusVMBoot,
	prometheusVMCPUAval,
	prometheusVMNumCPU,
	prometheusVMMemAval,
	prometheusVMMemUsage,
	prometheusVMCPUUsage,
	prometheusVMNetRec *prometheus.GaugeVec

	last time.Time
}

// Options 选项
type Options struct {
	Host, Username, Password string
}

func (o Options) mac() string {
	var buf bytes.Buffer
	defer buf.Reset()
	buf.WriteString(o.Host)
	buf.WriteString(o.Username)
	buf.WriteString(o.Password)
	arr := sha1.Sum(buf.Bytes())
	return hex.EncodeToString(arr[:])
}

// Valid 验证请求参数
func (o *Options) Valid() error {
	if o.Host == "" {
		return errors.New("host is empty")
	}
	if o.Username == "" {
		return errors.New("username is empty")
	}
	if o.Password == "" {
		return errors.New("password is empty")
	}
	return nil
}

// NewVMMetrics 新建VMMetrics指标
func NewVMMetrics(opts *Options) (vm *VMMetrics) {
	vm = &VMMetrics{
		host:     opts.Host,
		username: opts.Username,
		password: opts.Password,
		registry: prometheus.NewRegistry(),
	}
	factory := promauto.With(vm.registry)
	vm.prometheusHostPowerState = createPrometheusHostPowerState(factory)
	vm.prometheusHostBoot = createPrometheusHostBoot(factory)
	vm.prometheusTotalCPU = createPrometheusTotalCPU(factory)
	vm.prometheusUsageCPU = createPrometheusUsageCPU(factory)
	vm.prometheusTotalMem = createPrometheusTotalMem(factory)
	vm.prometheusUsageMem = createPrometheusUsageMem(factory)
	vm.prometheusDiskOk = createPrometheusDiskOk(factory)
	vm.prometheusTotalDs = createPrometheusTotalDs(factory)
	vm.prometheusUsageDs = createPrometheusUsageDs(factory)
	vm.prometheusVMBoot = createPrometheusVMBoot(factory)
	vm.prometheusVMCPUAval = createPrometheusVMCPUAval(factory)
	vm.prometheusVMNumCPU = createPrometheusVMNumCPU(factory)
	vm.prometheusVMMemAval = createPrometheusVMMemAval(factory)
	vm.prometheusVMMemUsage = createPrometheusVMMemUsage(factory)
	vm.prometheusVMCPUUsage = createprometheusVMCPUUsage(factory)
	vm.prometheusVMNetRec = createPrometheusVMNetRec(factory)
	return
}

func convertTime(vm mo.VirtualMachine) float64 {
	if vm.Summary.Runtime.BootTime == nil {
		return 0
	}
	return float64(vm.Summary.Runtime.BootTime.Unix())
}

func powerState(s types.HostSystemPowerState) float64 {
	if s == "poweredOn" {
		return 1
	}
	if s == "poweredOff" {
		return 2
	}
	if s == "standBy" {
		return 3
	}
	return 0
}

func totalCPU(hs mo.HostSystem) float64 {
	totalCPU := int64(hs.Summary.Hardware.CpuMhz) * int64(hs.Summary.Hardware.NumCpuCores)
	return float64(totalCPU)
}

func outputLogger(logger *log.Logger, level, format string, v ...interface{}) {
	if logger == nil {
		return
	}
	switch level {
	case "debug":
		logger.Debugf(format, v...)
	case "info":
		logger.Infof(format, v...)
	case "warn":
		logger.Warnf(format, v...)
	case "error":
		logger.Errorf(format, v...)
	default:
		logger.Printf(format, v...)
	}
}

// scrapeHostMetrics 采集宿主机指标
func (vm *VMMetrics) scrapeHostMetrics(ctx context.Context, logger *log.Logger) (err error) {
	// outputLogger(logger, "scrape vm %s datastore", vm.host)
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("scrapeHostMetrics panic: %s", e)
		}
	}()
	c, err := newClient(ctx, vm.host, vm.username, vm.password)
	if err != nil {
		// outputLogger(logger, "warn", logHostMetrics, vm.host, err)
		return fmt.Errorf("scrapeHostMetrics create vm client error: %w", err)
	}
	defer c.Logout(ctx)
	m := view.NewManager(c.Client)
	v, err := m.CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"HostSystem"}, true)
	if err != nil {
		// outputLogger(logger, "warn", logHostMetrics, vm.host, err)
		return fmt.Errorf("scrapeHostMetrics createContainerView error: %w", err)
	}
	defer v.Destroy(ctx)
	var hss []mo.HostSystem
	err = v.Retrieve(ctx, []string{"HostSystem"}, []string{"summary"}, &hss)
	if err != nil {
		// outputLogger(logger, "warn", logHostMetrics, vm.host, err)
		return fmt.Errorf("scrapeHostMetrics retrieve error: %w", err)
	}
	for _, hs := range hss {
		vm.prometheusHostPowerState.WithLabelValues(vm.host).Set(powerState(hs.Summary.Runtime.PowerState))
		vm.prometheusHostBoot.WithLabelValues(vm.host).Set(float64(hs.Summary.Runtime.BootTime.Unix()))
		vm.prometheusTotalCPU.WithLabelValues(vm.host).Set(totalCPU(hs))
		vm.prometheusUsageCPU.WithLabelValues(vm.host).Set(float64(hs.Summary.QuickStats.OverallCpuUsage))
		vm.prometheusTotalMem.WithLabelValues(vm.host).Set(float64(hs.Summary.Hardware.MemorySize))
		vm.prometheusUsageMem.WithLabelValues(vm.host).Set(float64(hs.Summary.QuickStats.OverallMemoryUsage) * 1024 * 1024)

	}
	finder := find.NewFinder(c.Client)
	hs, err := finder.DefaultHostSystem(ctx)
	if err != nil {
		// outputLogger(logger, "warn", logHostMetrics, vm.host, err)
		return fmt.Errorf("scrapeHostMetrics find.DefaultHostSystem error: %w", err)
	}
	ss, err := hs.ConfigManager().StorageSystem(ctx)
	if err != nil {
		// outputLogger(logger, "warn", logHostMetrics, vm.host, err)
		return fmt.Errorf("scrapeHostMetrics read storage error: %w", err)
	}
	var hostss mo.HostStorageSystem
	err = ss.Properties(ctx, ss.Reference(), nil, &hostss)
	if err != nil {
		// outputLogger(logger, "warn", logHostMetrics, vm.host, err)
		return fmt.Errorf("scrapeHostMetrics read storage error: %w", err)
	}
	for _, e := range hostss.StorageDeviceInfo.ScsiLun {
		lun := e.GetScsiLun()
		ok := 1.0
		for _, s := range lun.OperationalState {
			if s != "ok" {
				ok = 0
				break
			}
		}
		vm.prometheusDiskOk.WithLabelValues(vm.host, lun.DeviceName).Set(ok)
	}
	return nil
}

// scrapeDsMetrics 采集datastore数据
func (vm *VMMetrics) scrapeDsMetrics(ctx context.Context, logger *log.Logger) (err error) {
	// outputLogger(logger, "scrape vm %s datastore", vm.host)
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("scrapeDsMetrics panic: %s", e)
		}
	}()
	c, err := newClient(ctx, vm.host, vm.username, vm.password)
	if err != nil {
		// outputLogger(logger, "warn", logDsMetrics, vm.host, err)
		return fmt.Errorf("scrapeDsMetrics create client error: %w", err)
	}
	defer c.Logout(ctx)
	m := view.NewManager(c.Client)
	v, err := m.CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"Datastore"}, true)
	if err != nil {
		// outputLogger(logger, "warn", logDsMetrics, vm.host, err)
		return fmt.Errorf("scrapeDsMetrics createContainerView error: %w", err)
	}
	defer v.Destroy(ctx)
	var dss []mo.Datastore
	err = v.Retrieve(ctx, []string{"Datastore"}, []string{"summary"}, &dss)
	if err != nil {
		// outputLogger(logger, "warn", logDsMetrics, vm.host, err)
		return fmt.Errorf("scrapeDsMetrics retrieve error: %w", err)
	}
	for _, ds := range dss {
		dsname := ds.Summary.Name
		vm.prometheusTotalDs.WithLabelValues(dsname, vm.host).Set(float64(ds.Summary.Capacity))
		vm.prometheusUsageDs.WithLabelValues(dsname, vm.host).Set(float64(ds.Summary.FreeSpace))
	}
	return nil
}

// scrapeGuestMetrics 采集虚拟机数据
func (vm *VMMetrics) scrapeGuestMetrics(ctx context.Context, logger *log.Logger) (err error) {
	// outputLogger(logger, "scrape vm %s guest", vm.host)
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("scrapeGuestMetric spanic: %s", e)
		}
	}()
	c, err := newClient(ctx, vm.host, vm.username, vm.password)
	if err != nil {
		// outputLogger(logger, "warn", logGuestMetrics, vm.host, err)
		return fmt.Errorf("scrapeGuestMetric create client error: %w", err)
	}
	defer c.Logout(ctx)
	m := view.NewManager(c.Client)
	v, err := m.CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"VirtualMachine"}, true)
	if err != nil {
		// outputLogger(logger, "warn", logGuestMetrics, vm.host, err)
		return fmt.Errorf("scrapeGuestMetric createContainerView error: %w", err)
	}
	defer v.Destroy(ctx)
	var vms []mo.VirtualMachine
	err = v.Retrieve(ctx, []string{"VirtualMachine"}, []string{"summary"}, &vms)
	if err != nil {
		// outputLogger(logger, "warn", logGuestMetrics, vm.host, err)
		return fmt.Errorf("scrapeGuestMetric retrieve error: %w", err)
	}
	for _, v := range vms {
		vmname := v.Summary.Config.Name
		vm.prometheusVMBoot.WithLabelValues(vmname, vm.host).Set(convertTime(v))
		vm.prometheusVMCPUAval.WithLabelValues(vmname, vm.host).Set(float64(v.Summary.Runtime.MaxCpuUsage) * 1000 * 1000)
		vm.prometheusVMCPUUsage.WithLabelValues(vmname, vm.host).Set(float64(v.Summary.QuickStats.OverallCpuUsage) * 1000 * 1000)
		vm.prometheusVMNumCPU.WithLabelValues(vmname, vm.host).Set(float64(v.Summary.Config.NumCpu))
		vm.prometheusVMMemAval.WithLabelValues(vmname, vm.host).Set(float64(v.Summary.Config.MemorySizeMB))
		vm.prometheusVMMemUsage.WithLabelValues(vmname, vm.host).Set(float64(v.Summary.QuickStats.GuestMemoryUsage) * 1024 * 1024)
	}
	return nil
}

// Scrape 采集虚拟机数据
func (vm *VMMetrics) Scrape(ctx context.Context, logger *log.Logger) error {
	ct := time.Now()
	// 设置最后一次请求时间
	vm.last = ct
	errs := make(chan error, 3)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		errs <- vm.scrapeHostMetrics(ctx, logger)
		wg.Done()
	}()
	go func() {
		errs <- vm.scrapeDsMetrics(ctx, logger)
		wg.Done()
	}()
	go func() {
		errs <- vm.scrapeGuestMetrics(ctx, logger)
		wg.Done()
	}()
	ss := make([]string, 0, 3)
	go func() {
		for {
			err, ok := <-errs
			// 通道关闭
			if !ok {
				outputLogger(logger, "debug", "get metrics of %s in %s done", vm.host, time.Since(ct))
				break
			}
			if err == nil {
				continue
			}
			ss = append(ss, err.Error())
		}
	}()
	wg.Wait()
	close(errs)
	if len(ss) == 0 {
		return nil
	}
	return errors.New(strings.Join(ss, ","))
}

// Handle 返回数据
func (vm *VMMetrics) Handle(w http.ResponseWriter, r *http.Request) {
	promhttp.HandlerFor(vm.registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}
