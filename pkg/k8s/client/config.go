// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

const OptUserAgent = "user-agent"

type Config struct {
	ClientParams
	SharedConfig
}

type SharedConfig struct {
	// EnableK8s is a flag that, when set to false, forcibly disables the clientset, to let cilium
	// operates with CNI-compatible orchestrators other than Kubernetes. Default to true.
	EnableK8s bool

	// K8sAPIServerURLs is the list of API server instances
	K8sAPIServerURLs []string

	// K8sAPIServer is the kubernetes api address server (for https use --k8s-kubeconfig-path instead)
	K8sAPIServer string

	// K8sKubeConfigPath is the absolute path of the kubernetes kubeconfig file
	K8sKubeConfigPath string

	// K8sClientConnectionTimeout configures the timeout for K8s client connections.
	K8sClientConnectionTimeout time.Duration

	// K8sClientConnectionKeepAlive configures the keep alive duration for K8s client connections.
	K8sClientConnectionKeepAlive time.Duration

	// K8sHeartbeatTimeout configures the timeout for apiserver heartbeat
	K8sHeartbeatTimeout time.Duration

	// EnableAPIDiscovery enables Kubernetes API discovery
	EnableK8sAPIDiscovery bool
}

type ClientParams struct {
	// K8sClientQPS is the queries per second limit for the K8s client. Defaults to k8s client defaults.
	K8sClientQPS float32

	// K8sClientBurst is the burst value allowed for the K8s client. Defaults to k8s client defaults.
	K8sClientBurst int
}

var defaultClientParams = ClientParams{
	K8sClientQPS:   defaults.K8sClientQPSLimit,
	K8sClientBurst: defaults.K8sClientBurst,
}

func (def ClientParams) Flags(flags *pflag.FlagSet) {
	flags.Float32(option.K8sClientQPSLimit, def.K8sClientQPS, "Queries per second limit for the K8s client")
	flags.Int(option.K8sClientBurst, def.K8sClientBurst, "Burst value allowed for the K8s client")
}

var defaultSharedConfig = SharedConfig{
	EnableK8s:                    true,
	K8sAPIServer:                 "",
	K8sAPIServerURLs:             []string{},
	K8sKubeConfigPath:            "",
	K8sClientConnectionTimeout:   30 * time.Second,
	K8sClientConnectionKeepAlive: 30 * time.Second,
	K8sHeartbeatTimeout:          30 * time.Second,
	EnableK8sAPIDiscovery:        defaults.K8sEnableAPIDiscovery,
}

func (def SharedConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool(option.EnableK8s, def.EnableK8s, "Enable the k8s clientset")
	flags.String(option.K8sAPIServer, def.K8sAPIServer, "Kubernetes API server URL")
	flags.MarkDeprecated(option.K8sAPIServer, fmt.Sprintf("use --%s", option.K8sAPIServerURLs))
	flags.StringSlice(option.K8sAPIServerURLs, def.K8sAPIServerURLs, "Kubernetes API server URLs")
	flags.String(option.K8sKubeConfigPath, def.K8sKubeConfigPath, "Absolute path of the kubernetes kubeconfig file")
	flags.Duration(option.K8sClientConnectionTimeout, def.K8sClientConnectionTimeout, "Configures the timeout of K8s client connections. K8s client is disabled if the value is set to 0")
	flags.Duration(option.K8sClientConnectionKeepAlive, def.K8sClientConnectionKeepAlive, "Configures the keep alive duration of K8s client connections. K8 client is disabled if the value is set to 0")
	flags.Duration(option.K8sHeartbeatTimeout, def.K8sHeartbeatTimeout, "Configures the timeout for api-server heartbeat, set to 0 to disable")
	flags.Bool(option.K8sEnableAPIDiscovery, def.EnableK8sAPIDiscovery, "Enable discovery of Kubernetes API groups and resources with the discovery API")
}

func NewClientConfig(cfg SharedConfig, params ClientParams) Config {
	return Config{
		SharedConfig: cfg,
		ClientParams: params,
	}
}

func (cfg Config) isEnabled() bool {
	if !cfg.EnableK8s {
		return false
	}
	return cfg.K8sAPIServer != "" ||
		len(cfg.K8sAPIServerURLs) >= 1 ||
		cfg.K8sKubeConfigPath != "" ||
		(os.Getenv("KUBERNETES_SERVICE_HOST") != "" &&
			os.Getenv("KUBERNETES_SERVICE_PORT") != "") ||
		os.Getenv("K8S_NODE_NAME") != ""
}
