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

package openstack

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/google/uuid"
	"k8s.io/klog"
)

// TODO(irozzo): Make client timeout customizable
const defaultClientTimeout = 15 * time.Second

// newHTTPClient return a custom HTTP client that allows for logging
// requests and responses with openstack API information before and after
// the HTTP request.
func newHTTPClient() http.Client {
	return http.Client{
		Transport: &LogRoundTripper{
			rt: http.DefaultTransport,
		},
		Timeout: defaultClientTimeout,
	}
}

// LogRoundTripper is used to log information about requests and responses that
// may be useful for debugging purposes.
// Note that setting log level >5 results in full dumps of requests and
// responses, including sensitive invormation (e.g. Authorization header).
type LogRoundTripper struct {
	rt http.RoundTripper
}

func (lrt *LogRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	var log []byte
	var err error
	// Generate unique ID to correlate requests and responses
	id := uuid.New()
	switch {
	case bool(klog.V(6)):
		log, err = httputil.DumpRequest(request, true)
		if err != nil {
			klog.Warningf("Error occurred while dumping request: %v", err)
		}
	case bool(klog.V(5)):
		log, err = httputil.DumpRequest(request, false)
		if err != nil {
			klog.Warningf("Error occurred while dumping request: %v", err)
		}
	default:
		var b bytes.Buffer
		fmt.Fprintf(&b, "%s %s HTTP/%d.%d", valueOrDefault(request.Method, "GET"),
			request.URL.RequestURI(), request.ProtoMajor, request.ProtoMinor)
		log = b.Bytes()
	}
	klog.V(1).Infof("OpenStack API request sent [%s]: %s\n", id.String(), string(log))

	response, err := lrt.rt.RoundTrip(request)
	if response == nil {
		return nil, err
	}

	switch {
	case bool(klog.V(6)):
		log, err = httputil.DumpResponse(response, true)
		if err != nil {
			klog.Warningf("Error occurred while dumping response: %v", err)
		}
	case bool(klog.V(5)):
		log, err = httputil.DumpResponse(response, false)
		if err != nil {
			klog.Warningf("Error occurred while dumping response: %v", err)
		}
	default:
		var b bytes.Buffer
		fmt.Fprintf(&b, "HTTP/%d.%d %03d", response.ProtoMajor, response.ProtoMinor, response.StatusCode)
		log = b.Bytes()
	}
	klog.V(1).Infof("OpenStack API request received [%s]: %s\n", id.String(), string(log))

	return response, nil
}

// Return value if nonempty, def otherwise.
func valueOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}