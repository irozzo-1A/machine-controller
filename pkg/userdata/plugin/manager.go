/*
Copyright 2019 The Machine Controller Authors.

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

//
// UserData plugin manager.
//

// Package manager provides the instantiation and
// running of the plugins on machine controller side.
package plugin

import (
	"errors"
	"flag"

	providerconfigtypes "github.com/kubermatic/machine-controller/pkg/providerconfig/types"

	"k8s.io/klog"
)

var (
	// ErrLocatingPlugins is returned when a new manager cannot locate
	// the plugins for the supported operating systems.
	ErrLocatingPlugins = errors.New("one or more user data plugins not found")

	// ErrPluginNotFound describes an invalid operating system for
	// a user data plugin. Here directory has to be checked if
	// correct ones are installed.
	ErrPluginNotFound = errors.New("no user data plugin for the given operating system found")

	// supportedOS contains a list of operating systems the machine
	// controller supports.
	supportedOS = []providerconfigtypes.OperatingSystem{
		providerconfigtypes.OperatingSystemCentOS,
		providerconfigtypes.OperatingSystemCoreos,
		providerconfigtypes.OperatingSystemUbuntu,
		providerconfigtypes.OperatingSystemSLES,
		providerconfigtypes.OperatingSystemRHEL,
	}
)

// Manager inits and manages the userdata plugins.
type Manager struct {
	debug   bool
	plugins map[providerconfigtypes.OperatingSystem]map[providerconfigtypes.OperatingSystemVersion]*PluginProxy
}

// NewManager returns an initialised plugin manager.
func NewManager() (*Manager, error) {
	m := &Manager{
		plugins: make(map[providerconfigtypes.OperatingSystem]map[providerconfigtypes.OperatingSystemVersion]*PluginProxy),
	}
	flag.BoolVar(&m.debug, "plugin-debug", false, "Switch for enabling the plugin debugging")
	m.locatePlugins()
	if len(m.plugins) < len(supportedOS) {
		return nil, ErrLocatingPlugins
	}
	return m, nil
}

// ForOS returns the plugin for the given operating system.
func (m *Manager) ForOS(os providerconfigtypes.OperatingSystem, version providerconfigtypes.OperatingSystemVersion) (p *PluginProxy, err error) {
	klog.V(1).Infof("Looking up for os %s version %s: %+v", os, version, m.plugins)
	var found bool
	if p, found = m.plugins[os][version]; !found {
		return nil, ErrPluginNotFound
	}
	return p, nil
}

// locatePlugins tries to find the plugins and inits their wrapper.
func (m *Manager) locatePlugins() {
	for _, os := range supportedOS {
		m.plugins[os] = map[providerconfigtypes.OperatingSystemVersion]*PluginProxy{}
		plugin, err := newPlugin(os, m.debug)
		if err != nil {
			klog.Errorf("cannot use plugin '%v': %v", os, err)
			continue
		}
		info, err := plugin.Info()
		if err != nil {
			klog.Errorf("error occurred while obtaining plugin information: %v", err)
			m.plugins[os][providerconfigtypes.DefaultOperatingSystemVersion] = plugin
		} else {
			for _, v := range info.SuppertedVersions {
				m.plugins[os][providerconfigtypes.OperatingSystemVersion(v)] = plugin
			}
		}
	}
}
