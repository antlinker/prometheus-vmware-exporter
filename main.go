package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"prometheus-vmware-exporter/internal/collector"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	listen      string
	logLevel    string
	timeout     int
	idleTimeout int64

	once   sync.Once
	logger *log.Logger
)

func init() {
	flag.StringVar(&listen, "listen", ":9512", "listen port")
	flag.StringVar(&logLevel, "log", "info", "Log level must be, debug or info")
	flag.IntVar(&timeout, "timeout", 1, "the seconds for request timeout")
	flag.Int64Var(&idleTimeout, "idle_timeout", 7200, "delete scrape metrics if greater then idle_timeout seconds since last request for host")
}

func getTimeout(s string) (d int, err error) {
	d, err = strconv.Atoi(s)
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

func handleMulti(w http.ResponseWriter, r *http.Request) {
	opts := &collector.Options{
		Host:     r.FormValue("host"),
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
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
	timeout := r.FormValue("timeout")
	d, err := getTimeout(timeout)
	if err != nil {
		logger.Errorf("timeout %s invalid %s, use %v seconds", timeout, err, d)
	}
	// logger.Infof("timeout: %s", d)
	// Handle 处理抓取请求
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(d)*time.Second)
	defer cancel()
	vm.Scrape(ctx, logger)
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
	p {
		margin: 5px;
	}
    </style>
  </head>
  <body>
    <h1>VMware Exporter</h1>
	<p><a href="/metrics">Metrics</a></p>
	<p>
        <form action="/vm"" id="vm>
            <label for="host">host: </label>
            <input type="text" name="host" for="vm" placeholder="enter host or ip">
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
	msg := fmt.Sprintf("Exporter start on port %s", listen)
	logger.Info(msg)
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
