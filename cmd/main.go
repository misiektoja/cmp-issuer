/*
Copyright 2026 The cmp-issuer Authors.

SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	cmpcontroller "github.com/misiektoja/cmp-issuer/internal/controller"
	"github.com/misiektoja/cmp-issuer/internal/version"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

// runConfiguration contains the manager settings populated by command-line flags.
type runConfiguration struct {
	ClusterResourceNamespace string
	WatchNamespace           string
	EnableLeaderElection     bool
	MetricsAddress           string
	MetricsSecure            bool
	MetricsCertificateDir    string
	MetricsCertificateName   string
	MetricsCertificateKey    string
	ProbeAddress             string
}

// init registers Kubernetes and cmp-issuer APIs.
func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(certmanagerv1.AddToScheme(scheme))
	utilruntime.Must(cmpv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// main parses controller flags and starts the manager.
func main() {
	var clusterResourceNamespace string
	var watchNamespace string
	var enableLeaderElection bool
	var metricsAddress string
	var metricsSecure bool
	var metricsCertificateDir string
	var metricsCertificateName string
	var metricsCertificateKey string
	var probeAddress string
	var printVersion bool
	flag.StringVar(
		&clusterResourceNamespace,
		"cluster-resource-namespace",
		"cmp-issuer-system",
		"Namespace containing CMPClusterIssuer credential Secrets",
	)
	flag.BoolVar(&enableLeaderElection, "leader-elect", true, "Enable controller leader election")
	flag.StringVar(
		&watchNamespace,
		"watch-namespace",
		"",
		"Restrict CMPIssuer and CertificateRequest reconciliation to one namespace and disable CMPClusterIssuer",
	)
	flag.StringVar(&metricsAddress, "metrics-bind-address", "0", "Metrics listener address or 0 to disable")
	flag.BoolVar(
		&metricsSecure,
		"metrics-secure",
		true,
		"Serve metrics over HTTPS, authenticated with TokenReview and authorized with SubjectAccessReview",
	)
	flag.StringVar(
		&metricsCertificateDir,
		"metrics-cert-path",
		"",
		"Directory holding the metrics serving certificate, or empty to generate a self-signed one",
	)
	flag.StringVar(&metricsCertificateName, "metrics-cert-name", "tls.crt", "Metrics serving certificate file name")
	flag.StringVar(&metricsCertificateKey, "metrics-cert-key", "tls.key", "Metrics serving key file name")
	flag.StringVar(&probeAddress, "health-probe-bind-address", ":8081", "Health probe listener address")
	flag.BoolVar(&printVersion, "version", false, "Print the build identity of this binary and exit")
	logOptions := zap.Options{Development: false}
	logOptions.BindFlags(flag.CommandLine)
	flag.Parse()
	if printVersion {
		fmt.Println(version.Get())
		return
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&logOptions)))
	configuration := runConfiguration{
		ClusterResourceNamespace: clusterResourceNamespace,
		WatchNamespace:           watchNamespace,
		EnableLeaderElection:     enableLeaderElection,
		MetricsAddress:           metricsAddress,
		MetricsSecure:            metricsSecure,
		MetricsCertificateDir:    metricsCertificateDir,
		MetricsCertificateName:   metricsCertificateName,
		MetricsCertificateKey:    metricsCertificateKey,
		ProbeAddress:             probeAddress,
	}
	if err := run(ctrl.SetupSignalHandler(), configuration); err != nil {
		setupLog.Error(err, "Manager exited")
		os.Exit(1)
	}
}

// run builds the controller-runtime manager and registers issuer-lib controllers.
func run(ctx context.Context, configuration runConfiguration) error {
	disableHTTP2 := func(configuration *tls.Config) { configuration.NextProtos = []string{"http/1.1"} }
	metricsOptions := metricsserver.Options{
		BindAddress:   configuration.MetricsAddress,
		SecureServing: configuration.MetricsSecure,
		TLSOpts:       []func(*tls.Config){disableHTTP2},
	}
	if configuration.MetricsSecure {
		// Without a filter the endpoint would serve HTTPS to any caller that reaches the port. The
		// filter delegates to the API server, so a scrape needs a token whose subject is allowed to
		// get the /metrics non-resource URL, which is what the metrics-reader ClusterRole grants.
		metricsOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	if configuration.MetricsCertificateDir != "" {
		// Left unset, the metrics server generates a certificate no authority signs, which a scrape
		// can only accept by skipping verification. Pointed at a directory, it watches these files and
		// picks up a rotated certificate without a restart.
		metricsOptions.CertDir = configuration.MetricsCertificateDir
		metricsOptions.CertName = configuration.MetricsCertificateName
		metricsOptions.KeyName = configuration.MetricsCertificateKey
		setupLog.Info(
			"Serving metrics with the supplied certificate",
			"path", configuration.MetricsCertificateDir,
			"certificate", configuration.MetricsCertificateName,
			"key", configuration.MetricsCertificateKey,
		)
	}
	managerOptions := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsOptions,
		WebhookServer:          webhook.NewServer(webhook.Options{TLSOpts: []func(*tls.Config){disableHTTP2}}),
		HealthProbeBindAddress: configuration.ProbeAddress,
		LeaderElection:         configuration.EnableLeaderElection,
		LeaderElectionID:       "4f0dc535.misiektoja.github.io",
	}
	if configuration.WatchNamespace != "" {
		managerOptions.Cache.DefaultNamespaces = map[string]cache.Config{configuration.WatchNamespace: {}}
	}
	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), managerOptions)
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}
	signer := &cmpcontroller.Signer{
		ClusterResourceNamespace: configuration.ClusterResourceNamespace,
		WatchNamespace:           configuration.WatchNamespace,
	}
	if err := signer.SetupWithManager(ctx, manager); err != nil {
		return fmt.Errorf("register CMP signer: %w", err)
	}
	// +kubebuilder:scaffold:builder
	if err := manager.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("add health check: %w", err)
	}
	if err := manager.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("add readiness check: %w", err)
	}
	setupLog.Info("Starting manager", version.Get().KeysAndValues()...)
	if err := manager.Start(ctx); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}
	return nil
}
