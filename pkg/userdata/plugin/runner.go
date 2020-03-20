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

package plugin

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kubermatic/machine-controller/pkg/apis/plugin"
	providerconfigtypes "github.com/kubermatic/machine-controller/pkg/providerconfig/types"

	"k8s.io/klog"
)

const (
	// pluginPrefix has to be the prefix of all plugin filenames.
	pluginPrefix = "machine-controller-userdata-"
)

// Ensures that PluginProxy implements the provider interface.
var _ Provider = &PluginProxy{}

// PluginProxy looks for the plugin executable and calls it for
// each request.
type PluginProxy struct {
	debug   bool
	command string
}

// newPlugin creates a new plugin manager. It starts the named
// binary and connects to it via net/rpc.
func newPlugin(os providerconfigtypes.OperatingSystem, debug bool) (*PluginProxy, error) {
	p := &PluginProxy{
		debug: debug,
	}
	if err := p.findPlugin(string(os)); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *PluginProxy) runCommand(args []string, env ...string) ([]byte, error) {
	argv := make([]string, len(args)+1, len(args))
	copy(argv, args)
	// Prepare command.
	if p.debug {
		argv = append(argv, "-debug")
	}
	cmd := exec.Command(p.command, argv...)
	cmd.Env = append(os.Environ(), env...)
	// Execute command.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute command %q: output: %q error: %q", p.command, string(out), err)
	}
	return out, nil
}

// UserData retrieves the user data of the given resource via
// plugin handling the communication.
func (p *PluginProxy) UserData(req plugin.UserDataRequest) (string, error) {
	// Set environment.
	reqj, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	env := fmt.Sprintf("%s=%s", plugin.EnvUserDataRequest, string(reqj))
	out, err := p.runCommand([]string{}, env)
	if err != nil {
		return "", fmt.Errorf("error occurred while running userdata command: %v", err)
	}
	var resp plugin.UserDataResponse
	err = json.Unmarshal(out, &resp)
	if err != nil {
		return "", fmt.Errorf("error occurred while unmarshaling userdata response: %v", err)
	}
	if resp.Err != "" {
		return "", fmt.Errorf("error occurred during userdata generation: %v", resp.Err)
	}
	return resp.UserData, nil
}

func (p *PluginProxy) Info() (*plugin.Info, error) {
	i, err := p.runCommand([]string{"-info"})
	if err != nil {
		return nil, fmt.Errorf("error occurred during info command execution: %v", err)
	}
	var resp plugin.Info
	err = json.Unmarshal(i, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// findPlugin tries to find the executable of the plugin.
func (p *PluginProxy) findPlugin(name string) error {
	filename := pluginPrefix + name
	klog.Infof("looking for plugin %q", filename)
	// Create list to search in.
	var dirs []string
	envDir := os.Getenv(plugin.EnvPluginDir)
	if envDir != "" {
		dirs = append(dirs, envDir)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	ownDir, _ := filepath.Split(executable)
	ownDir, err = filepath.Abs(ownDir)
	if err != nil {
		return err
	}
	dirs = append(dirs, ownDir)
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	dirs = append(dirs, workingDir)
	path := os.Getenv("PATH")
	pathDirs := strings.Split(path, string(os.PathListSeparator))
	dirs = append(dirs, pathDirs...)
	// Now take a look.
	for _, dir := range dirs {
		command := dir + string(os.PathSeparator) + filename
		klog.V(3).Infof("checking %q", command)
		fi, err := os.Stat(command)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("error when looking for %q: %v", command, err)
		}
		if fi.IsDir() || (fi.Mode()&0111 == 0) {
			klog.Infof("found '%s', but is no executable", command)
			continue
		}
		p.command = command
		klog.Infof("found '%s'", command)
		return nil
	}
	klog.Errorf("did not find '%s'", filename)
	return ErrPluginNotFound
}
