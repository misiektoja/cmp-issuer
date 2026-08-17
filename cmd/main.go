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

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	cmpcontroller "github.com/misiektoja/cmp-issuer/internal/controller"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
	// Version is replaced by release builds.
	Version = "development"
)

// runConfiguration contains the manager settings populated by command-line flags.
type runConfiguration struct {
	ClusterResourceNamespace string
	EnableLeaderElection     bool
	MetricsAddress           string
	ProbeAddress             string
}

// init registers Kubernetes and cmp-issuer APIs.
func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cmpv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

// main parses controller flags and starts the manager.
func main() {
	var clusterResourceNamespace string
	var enableLeaderElection bool
	var metricsAddress string
	var probeAddress string
	flag.StringVar(
		&clusterResourceNamespace,
		"cluster-resource-namespace",
		"cmp-issuer-system",
		"Namespace containing CMPClusterIssuer credential Secrets",
	)
	flag.BoolVar(&enableLeaderElection, "leader-elect", true, "Enable controller leader election")
	flag.StringVar(&metricsAddress, "metrics-bind-address", "0", "Metrics listener address or 0 to disable")
	flag.StringVar(&probeAddress, "health-probe-bind-address", ":8081", "Health probe listener address")
	logOptions := zap.Options{Development: false}
	logOptions.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&logOptions)))
	configuration := runConfiguration{
		ClusterResourceNamespace: clusterResourceNamespace,
		EnableLeaderElection:     enableLeaderElection,
		MetricsAddress:           metricsAddress,
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
	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:   configuration.MetricsAddress,
			SecureServing: true,
			TLSOpts:       []func(*tls.Config){disableHTTP2},
		},
		WebhookServer:          webhook.NewServer(webhook.Options{TLSOpts: []func(*tls.Config){disableHTTP2}}),
		HealthProbeBindAddress: configuration.ProbeAddress,
		LeaderElection:         configuration.EnableLeaderElection,
		LeaderElectionID:       "4f0dc535.misiektoja.github.io",
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}
	signer := &cmpcontroller.Signer{ClusterResourceNamespace: configuration.ClusterResourceNamespace}
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
	setupLog.Info("Starting manager", "version", Version)
	if err := manager.Start(ctx); err != nil {
		return fmt.Errorf("run manager: %w", err)
	}
	return nil
}
