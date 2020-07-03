package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/antlinker/prometheus-vmware-exporter/internal/collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	log "github.com/sirupsen/logrus"
)

var (
	listen                = ":9512"
	logLevel              = "info"
	timeout         int64 = 5
	defaultUsername string
	defaultPassword string
	idleTimeout     int64 = 7200

	once   sync.Once
	logger *log.Logger
)

func init() {
	flag.StringVar(&listen, "listen", env("ESX_LISTEN", listen), "Listen port,the default value can be overridden by ESX_LISTEN")
	flag.StringVar(&defaultUsername, "username", env("ESX_USERNAME", defaultUsername), "The default username if not provided in the request, the default value can be overridden by ESX_USERNAME")
	flag.StringVar(&defaultPassword, "password", env("ESX_PASSWORD", defaultPassword), "The default password if not provided in the request,the default value can be overridden by ESX_PASSWORD")
	flag.StringVar(&logLevel, "log", env("ESX_LOG", logLevel), "Log level must be debug or info, the default value can be overridden by ESX_LOG")
	flag.Int64Var(&timeout, "timeout", envInt64("ESX_TIMEOUT", timeout), "The seconds for request timeout, the default value can be overridden by ESX_TIMEOUT")
	flag.Int64Var(&idleTimeout, "idle_timeout", envInt64("ESX_IDLE_TIMEOUT", 7200), "The host is requested beyond the specified idle seconds will be deleted, the default value can be overridden by ESX_IDLE_TIMEOUT")

	prometheus.MustRegister(version.NewCollector(collector.Namespace + "_exporter"))
}

func getTimeout(s string) (d int64, err error) {
	if s == "" {
		return timeout, nil
	}
	d, err = strconv.ParseInt(s, 10, 0)
	if err != nil {
		d = timeout
	}
	if d <= 0 {
		d = timeout
	} else if d > 60 {
		d = 60
	}
	return
}

func env(key, def string) string {
	if x := os.Getenv(key); x != "" {
		return x
	}
	return def
}

func envInt64(key string, def int64) int64 {
	x := os.Getenv(key)
	if x == "" {
		return def
	}
	n, err := strconv.ParseInt(x, 10, 0)
	if err != nil {
		return def
	}

	return n

}

func handleMulti(w http.ResponseWriter, r *http.Request) {
	opts := &collector.Options{
		Host:     r.FormValue("target"),
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}
	if opts.Username == "" {
		opts.Username = defaultUsername
	}
	if opts.Password == "" {
		opts.Password = defaultPassword
	}
	vm, err := collector.Get(opts, logger)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%s", err)
		return
	}
	if vm == nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "读取指标失败")
		return
	}
	// logger.Debugf("target:%s,username:%s,password:%s", opts.Host, opts.Username, opts.Password)
	timeout := r.FormValue("timeout")
	d, err := getTimeout(timeout)
	if err != nil {
		logger.Errorf("timeout %s invalid %s, use %v seconds", timeout, err, d)
	}
	// Handle 处理抓取请求
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(d)*time.Second)
	defer cancel()
	if err := vm.Scrape(ctx, logger); err != nil {
		logger.Errorf("vm.Scrape %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s", err)
		return
	}
	vm.Handle(w, r)
}

func initLogger() {
	if logger != nil {
		return
	}
	once.Do(func() {
		logger = log.New()
		logrusLogLevel, err := log.ParseLevel(logLevel)
		if err != nil {
			log.Fatalln(err)
		}
		logger.SetLevel(logrusLogLevel)
		logger.Formatter = &log.TextFormatter{DisableTimestamp: false, FullTimestamp: true}
	})
	return
}

const htmlStr = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>VMware Exporter</title>
	<style>
	p { margin: 5px; }
	label {	margin: 5px; }
	input { margin: 5px; }
    </style>
  </head>
  <body>
    <h1>VMware Exporter</h1>
	<p><a href="/metrics">Metrics</a></p>
	<p>
		<form action="/vm"" id="vm">
            <label for="target">target: </label>
            <input type="text" name="target" for="vm" placeholder="enter target host or ip">
            <br>
            <label for="username">username: </label>
            <input type="text" name="username" for="vm" placeholder="username">
            <br>
            <label for="password">password: </label>
            <input type="text" name="password" for="vm" placeholder="password">
            <br>
            <label for="timeout">timeout: </label>
            <input type="text" name="timeout" for="vm" value="5" placeholder="the seconds request timeout">
            <br>
            <input type="submit" value="查询">
        </form>
    </p>
  </body>
</html>`

func main() {
	flag.Parse()
	initLogger()

	logger.Infof("Start %s_exporter version: %s", collector.Namespace, version.Info())
	logger.Infof("Build context: %s", version.BuildContext())
	logger.Info("The metrics path: /metrics")
	logger.Info("The vmware ESXi path: /vm")
	logger.Infof("Http listen address: %s", listen)

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/vm", handleMulti)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, htmlStr)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go collector.StartGC(ctx, time.Duration(idleTimeout)*time.Second, logger)
	logger.Fatal(http.ListenAndServe(listen, nil))
}
