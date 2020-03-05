package coreos

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
	ctconfig "github.com/coreos/container-linux-config-transpiler/config"
	cttypes "github.com/coreos/container-linux-config-transpiler/config/types"
	ign "github.com/coreos/ignition/config/v2_2"
	igntypes "github.com/coreos/ignition/config/v2_2/types"
	//"github.com/kubernetes/klog"
	"gopkg.in/yaml.v2"
)

const (
	filesDir = "files"
	unitsDir = "units"

	// TODO: these constants are wrong, they should match what is reported by the infrastructure provider
	platformAWS       = "aws"
	platformAzure     = "azure"
	platformBaremetal = "baremetal"
	platformGCP       = "gcp"
	platformOpenStack = "openstack"
	platformLibvirt   = "libvirt"
	platformNone      = "none"
	platformVSphere   = "vsphere"
	platformBase      = "_base"
)

type ProxyStatus struct {
	// httpProxy is the URL of the proxy for HTTP requests.
	// +optional
	HTTPProxy string `json:"httpProxy,omitempty"`

	// httpsProxy is the URL of the proxy for HTTPS requests.
	// +optional
	HTTPSProxy string `json:"httpsProxy,omitempty"`

	// noProxy is a comma-separated list of hostnames and/or CIDRs for which the proxy should not be used.
	// +optional
	NoProxy string `json:"noProxy,omitempty"`
}

type RenderConfig struct {
	// clusterDNSIP is the cluster DNS IP address
	ClusterDNSIP string `json:"clusterDNSIP"`

	// cloudProviderConfig is the configuration for the given cloud provider
	CloudProviderConfig string `json:"cloudProviderConfig"`

	// TODO: Use PlatformType instead of string

	// The openshift platform, e.g. "libvirt", "openstack", "gcp", "baremetal", "aws", or "none"
	Platform string `json:"platform"`

	// etcdDiscoveryDomain specifies the etcd discovery domain
	EtcdDiscoveryDomain string `json:"etcdDiscoveryDomain"`

	// TODO: Use string for CA data

	// kubeAPIServerServingCAData managed Kubelet to API Server Cert... Rotated automatically
	KubeAPIServerServingCAData []byte `json:"kubeAPIServerServingCAData"`

	// etcdCAData specifies the etcd CA data
	EtcdCAData []byte `json:"etcdCAData"`

	// etcdMetricData specifies the etcd metric CA data
	EtcdMetricCAData []byte `json:"etcdMetricCAData"`

	// rootCAData specifies the root CA data
	RootCAData []byte `json:"rootCAData"`

	// additionalTrustBundle is a certificate bundle that will be added to the nodes
	// trusted certificate store.
	AdditionalTrustBundle []byte `json:"additionalTrustBundle"`

	// TODO: Investigate using a ConfigMapNameReference for the PullSecret and OSImageURL

	// pullSecret is the default pull secret that needs to be installed
	// on all machines.
	PullSecret []byte `json:"pullSecret"`

	// images is map of images that are used by the controller to render templates under ./templates/
	Images map[string]string `json:"images"`

	// osImageURL is the location of the container image that contains the OS update payload.
	// Its value is taken from the data.osImageURL field on the machine-config-osimageurl ConfigMap.
	OSImageURL string `json:"osImageURL"`

	// proxy holds the current proxy configuration for the nodes
	Proxy ProxyStatus `json:"proxy"`
}

type NamedIgnitionConfig struct {
	Name   string
	Config igntypes.Config
}

func defaultSSHConfig(sshKeys []string) []*NamedIgnitionConfig {
	authKeys := []igntypes.SSHAuthorizedKey{}
	for _, key := range sshKeys {
		authKeys = append(authKeys, igntypes.SSHAuthorizedKey(key))
	}
	return []*NamedIgnitionConfig{
		&NamedIgnitionConfig{
			Name: "99-worker-ssh",
			Config: igntypes.Config{
				Passwd: igntypes.Passwd{
					Users: []igntypes.PasswdUser{
						igntypes.PasswdUser{
							Name:              "core",
							SSHAuthorizedKeys: authKeys,
						},
					},
				},
			},
		},
	}
}

// GenerateIgnition
func GenerateIgnitionForRole(config *RenderConfig, defaultConf []*NamedIgnitionConfig, role, templateDir string) (*igntypes.Config, error) {
	path := filepath.Join(templateDir, role)
	infos, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read dir %q: %v", path, err)
	}

	cfgs := defaultConf
	for _, info := range infos {
		if !info.IsDir() {
			//klog.Infof("ignoring non-directory path %q", info.Name())
			continue
		}
		name := info.Name()
		namePath := filepath.Join(path, name)
		nameConfig, err := generateIgnitionForName(config, role, name, templateDir, namePath)
		if err != nil {
			return nil, err
		}
		cfgs = append(cfgs, nameConfig)
	}

	return MergeIgnitionConfigs(cfgs), nil
}

func generateIgnitionForName(config *RenderConfig, role, name, templateDir, path string) (*NamedIgnitionConfig, error) {
	platform, err := platformFromControllerConfigSpec(config.Platform)
	if err != nil {
		return nil, err
	}

	platformDirs := []string{}
	// Loop over templates/common which applies everywhere
	for _, dir := range []string{platformBase, platform} {
		// Bypass OpenStack template rendering until
		// https://github.com/openshift/installer/pull/1959 merges
		/**if dir == platformOpenStack && config.ControllerConfigSpec.Infra.Status.PlatformStatus.OpenStack == nil {
			continue
		}**/
		basePath := filepath.Join(templateDir, "common", dir)
		exists, err := existsDir(basePath)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		platformDirs = append(platformDirs, basePath)
	}
	// And now over the target e.g. templates/master
	for _, dir := range []string{platformBase, platform} {
		// Bypass OpenStack template rendering until
		// https://github.com/openshift/installer/pull/1959 merges
		/*if dir == platformOpenStack && config.ControllerConfigSpec.Infra.Status.PlatformStatus.OpenStack == nil {
			continue
		}*/
		platformPath := filepath.Join(path, dir)
		exists, err := existsDir(platformPath)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		platformDirs = append(platformDirs, platformPath)
	}

	files := map[string]string{}
	units := map[string]string{}
	// walk all role dirs, with later ones taking precedence
	for _, platformDir := range platformDirs {
		p := filepath.Join(platformDir, filesDir)
		exists, err := existsDir(p)
		if err != nil {
			return nil, err
		}
		if exists {
			if err := filterTemplates(files, p, config); err != nil {
				return nil, err
			}
		}

		p = filepath.Join(platformDir, unitsDir)
		exists, err = existsDir(p)
		if err != nil {
			return nil, err
		}
		if exists {
			if err := filterTemplates(units, p, config); err != nil {
				return nil, err
			}
		}
	}

	// keySortVals returns a list of values, sorted by key
	// we need the lists of files and units to have a stable ordering for the checksum
	keySortVals := func(m map[string]string) []string {
		ks := []string{}
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)

		vs := []string{}
		for _, k := range ks {
			vs = append(vs, m[k])
		}

		return vs
	}

	ignCfg, err := transpileToIgn(keySortVals(files), keySortVals(units))
	if err != nil {
		return nil, fmt.Errorf("error transpiling ct config to Ignition config: %v", err)
	}

	/**mcfg := MachineConfigFromIgnConfig(role, name, ignCfg)
	// And inject the osimageurl here
	mcfg.Spec.OSImageURL = config.OSImageURL**/

	return &NamedIgnitionConfig{
		Name:   name,
		Config: *ignCfg,
	}, nil
}

func platformFromControllerConfigSpec(platform string) (string, error) {
	switch platform {
	case "":
		// if Platform is nil, return nil platform and an error message
		return "", fmt.Errorf("cannot generate MachineConfigs when no platform is set")
	case platformBase:
		return "", fmt.Errorf("platform _base unsupported")
	case platformAWS, platformAzure, platformBaremetal, platformGCP, platformOpenStack, platformLibvirt, platformNone:
		return platform, nil
	default:
		// platformNone is used for a non-empty, but currently unsupported platform.
		// This allows us to incrementally roll out new platforms across the project
		// by provisioning platforms before all support is added.
		//klog.Warningf("Warning: the controller config referenced an unsupported platform: %s", platform)
		return platformNone, nil
	}
}

// existsDir returns true if path exists and is a directory, false if the path
// does not exist, and error if there is a runtime error or the path is not a directory
func existsDir(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to open dir %q: %v", path, err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("expected template directory, %q is not a directory", path)
	}
	return true, nil
}

func filterTemplates(toFilter map[string]string, path string, config *RenderConfig) error {
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// empty templates signify don't create
		if info.Size() == 0 {
			delete(toFilter, info.Name())
			return nil
		}

		filedata, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %q: %v", path, err)
		}

		// Render the template file
		renderedData, err := renderTemplate(*config, path, filedata)
		if err != nil {
			return err
		}
		toFilter[info.Name()] = string(renderedData)
		return nil
	}

	return filepath.Walk(path, walkFn)
}

// renderTemplate renders a template file with values from a RenderConfig
// returns the rendered file data
func renderTemplate(config RenderConfig, path string, b []byte) ([]byte, error) {
	funcs := sprig.TxtFuncMap()
	funcs["skip"] = skipMissing
	funcs["etcdServerCertDNSNames"] = etcdServerCertDNSNames
	funcs["etcdPeerCertDNSNames"] = etcdPeerCertDNSNames
	funcs["cloudProvider"] = cloudProvider
	funcs["cloudConfigFlag"] = cloudConfigFlag
	tmpl, err := template.New(path).Funcs(funcs).Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("failed to parse template %s: %v", path, err)
	}

	buf := new(bytes.Buffer)
	if err := tmpl.Execute(buf, config); err != nil {
		return nil, fmt.Errorf("failed to execute template: %v", err)
	}

	return buf.Bytes(), nil
}

var skipKeyValidate = regexp.MustCompile(`^[_a-z]\w*$`)

// Keys labelled with skip ie. {{skip "key"}}, don't need to be templated in now because at Ignition request they will be templated in with query params
func skipMissing(key string) (interface{}, error) {
	if !skipKeyValidate.Match([]byte(key)) {
		return nil, fmt.Errorf("invalid key for skipKey")
	}

	return fmt.Sprintf("{{.%s}}", key), nil
}

// Process the {{etcdPeerCertDNSNames}} and {{etcdServerCertDNSNames}}
func etcdServerCertDNSNames(cfg RenderConfig) (interface{}, error) {
	var dnsNames = []string{
		"localhost",
		"etcd.kube-system.svc",                  // sign for the local etcd service name that cluster-network apiservers use to communicate
		"etcd.kube-system.svc.cluster.local",    // sign for the local etcd service name that cluster-network apiservers use to communicate
		"etcd.openshift-etcd.svc",               // sign for the local etcd service name that cluster-network apiservers use to communicate
		"etcd.openshift-etcd.svc.cluster.local", // sign for the local etcd service name that cluster-network apiservers use to communicate
		"${ETCD_WILDCARD_DNS_NAME}",
	}
	return strings.Join(dnsNames, ","), nil
}

func etcdPeerCertDNSNames(cfg RenderConfig) (interface{}, error) {
	if cfg.EtcdDiscoveryDomain == "" {
		return nil, fmt.Errorf("invalid configuration")
	}

	var dnsNames = []string{
		"${ETCD_DNS_NAME}",
		cfg.EtcdDiscoveryDomain, // https://github.com/etcd-io/etcd/blob/583763261f1c843e07c1bf7fea5fb4cfb684fe87/Documentation/op-guide/clustering.md#dns-discovery
	}
	return strings.Join(dnsNames, ","), nil
}

func cloudProvider(cfg RenderConfig) (interface{}, error) {
	switch cfg.Platform {
	case platformAWS, platformAzure, platformOpenStack, platformVSphere:
		return cfg.Platform, nil
	case platformGCP:
		return "gce", nil
	default:
		return "", nil
	}
}

// Process the {{cloudConfigFlag .}}
// If the CloudProviderConfig field is set and not empty, this
// returns the cloud conf flag for kubelet [1] pointing the kubelet to use
// /etc/kubernetes/cloud.conf for configuring the cloud provider for select platforms.
// By default, even if CloudProviderConfig fields is set, the kubelet will be configured to be
// used for select platforms only.
//
// [1]: https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/#options
func cloudConfigFlag(cfg RenderConfig) interface{} {
	if cfg.CloudProviderConfig == "" {
		return ""
	}
	flag := "--cloud-config=/etc/kubernetes/cloud.conf"
	switch cfg.Platform {
	case platformAzure, platformOpenStack:
		return flag
	default:
		return ""
	}
}

func transpileToIgn(files, units []string) (*igntypes.Config, error) {
	var ctCfg cttypes.Config

	// Convert data to Ignition resources
	for _, d := range files {
		f := new(cttypes.File)
		if err := yaml.Unmarshal([]byte(d), f); err != nil {
			return nil, fmt.Errorf("failed to unmarshal file into struct: %v", err)
		}

		// Add the file to the config
		ctCfg.Storage.Files = append(ctCfg.Storage.Files, *f)
	}

	for _, d := range units {
		u := new(cttypes.SystemdUnit)
		if err := yaml.Unmarshal([]byte(d), u); err != nil {
			return nil, fmt.Errorf("failed to unmarshal systemd unit into struct: %v", err)
		}

		// Add the unit to the config
		ctCfg.Systemd.Units = append(ctCfg.Systemd.Units, *u)
	}

	ignCfg, rep := ctconfig.Convert(ctCfg, "", nil)
	if rep.IsFatal() {
		return nil, fmt.Errorf("failed to convert config to Ignition config %s", rep)
	}

	return &ignCfg, nil
}

func MergeIgnitionConfigs(configs []*NamedIgnitionConfig) *igntypes.Config {
	if len(configs) == 0 {
		return nil
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].Name < configs[j].Name })

	outIgn := configs[0].Config
	for idx := 1; idx < len(configs); idx++ {
		outIgn = ign.Append(outIgn, configs[idx].Config)
	}
	return &outIgn
}
