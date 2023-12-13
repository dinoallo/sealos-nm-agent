// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exporter

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dinoallo/sealos-networkmanager-agent/store"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"go.uber.org/zap"
)

const (
	namespace = "sealos-networkmanager-agent" // For Prometheus metrics.
)

var (
	bytecountLabelNames = []string{"addr", "port"}
	storageLabelNames   = []string{}
	serverLabelNames    = []string{}

	loggerNotInitErr error = fmt.Errorf("the logger of the exporter has not been initialized")
)

type metricInfo struct {
	Desc *prometheus.Desc
	Type prometheus.ValueType
}

func newBytecountMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "bytecount", metricName),
			docString,
			bytecountLabelNames,
			constLabels,
		),
		Type: t,
	}
}

func newStorageMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "storage", metricName),
			docString,
			storageLabelNames,
			constLabels,
		),
		Type: t,
	}
}

func newServerMetric(metricName string, docString string, t prometheus.ValueType, constLabels prometheus.Labels) metricInfo {
	return metricInfo{
		Desc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "server", metricName),
			docString,
			serverLabelNames,
			constLabels,
		),
		Type: t,
	}
}

type metrics map[int]metricInfo

func (m metrics) String() string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	s := make([]string, len(keys))
	for i, k := range keys {
		s[i] = strconv.Itoa(k)
	}
	return strings.Join(s, ",")
}

// TODO: total tcp/udp requests, total ipv4/ipv6 requests...
var (
	bytecountBytesRecv metricInfo = newBytecountMetric("bytes_recv", "The bytes sent to an IP", prometheus.CounterValue, nil)
	bytecountBytesSent metricInfo = newBytecountMetric("bytes_sent", "The bytes sent from an IP", prometheus.CounterValue, nil)
	// bytecountSampleLost metricInfo = newBytecountMetric("sample_lost", "The samples lost", prometheus.CounterValue, nil)
	// agentInfo    = prometheus.NewDesc(prometheus.BuildFQName(namespace, "version", "info"), "Sealos networkmanager agent version info.", []string{"release_date", "version"}, nil)
	// agentUp      = prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "up"), "Was the last scrape of agent successful.", nil, nil)
	// agentIdlePct = prometheus.NewDesc(prometheus.BuildFQName(namespace, "process_idle_time", "percent"), "Time spent waiting for events instead of processing them.", nil, nil)
)

// Exporter collects stats and exports them using
// the prometheus metrics package.
type Exporter struct {
	logger  *zap.SugaredLogger
	reports chan *store.TrafficReport
}

// NewExporter returns an initialized Exporter.
func NewExporter(parentLogger *zap.SugaredLogger, reports chan *store.TrafficReport) (*Exporter, error) {
	if parentLogger == nil {
		return nil, loggerNotInitErr
	}
	logger := parentLogger.With("component", "exporter")

	return &Exporter{
		logger:  logger,
		reports: reports,
	}, nil
}

// Describe describes all the metrics ever exported by the exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- bytecountBytesRecv.Desc
	ch <- bytecountBytesSent.Desc
	// ch <- bytecountSampleLost.Desc
}

// Collect fetches the stats from the agent and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	report := <-e.reports
	var addr string
	var port string
	addr = report.SrcIP.String()
	port = fmt.Sprint(report.SrcPort)
	labels := []string{addr, port}
	switch report.Dir {
	case store.V4Egress:
		ch <- prometheus.MustNewConstMetric(bytecountBytesSent.Desc, bytecountBytesSent.Type, float64(report.DataBytes), labels...)
	case store.V4Ingress:
		ch <- prometheus.MustNewConstMetric(bytecountBytesRecv.Desc, bytecountBytesRecv.Type, float64(report.DataBytes), labels...)

	}
}

func (e *Exporter) Launch(ctx context.Context) error {

	logger := e.logger
	if e.logger == nil {
		return loggerNotInitErr
	}

	logger.Info("prometheus exporter for agent has started")

	prometheus.MustRegister(e)
	prometheus.MustRegister(version.NewCollector("sealos_networkmanager_agent_exporter"))

	metricsPath := "/metrics"

	http.Handle(metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>Sealos NetworkmanagerAgent Exporter</title></head>
             <body>
             <h1>Exporter</h1>
             <p><a href='` + metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	srv := &http.Server{
		Addr: ":9101",
	}
	webConfig := web.FlagConfig{}
	promlogConfig := &promlog.Config{}
	promLogger := promlog.New(promlogConfig)
	go func() {
		if err := web.ListenAndServe(srv, &webConfig, promLogger); err != nil && err != http.ErrServerClosed {
			logger.Info(err)
		}
	}()
	go func(ctx context.Context) {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Info(err)
		}
	}(ctx)
	return nil
}
