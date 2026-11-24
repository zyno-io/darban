package main

import (
	"context"
	"net/url"
	"strings"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	discoveryclient "k8s.io/client-go/kubernetes/typed/discovery/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type endpointState string

const (
	endpointReady         endpointState = "ready"
	endpointEmpty         endpointState = "no_ready_endpoints"
	endpointUnknown       endpointState = "unknown"
	endpointLocal         endpointState = "local"
	endpointNotConfigured endpointState = "not_configured"
)

type endpointCatalog map[string]cache.SharedIndexInformer

func serviceReference(origin string) (string, string) {
	address, err := url.Parse(origin)
	if err != nil || !serviceDNS.MatchString(address.Hostname()) {
		return "", ""
	}
	parts := strings.SplitN(address.Hostname(), ".", 3)
	return parts[0], parts[1]
}

// newEndpointCatalog watches EndpointSlices in the namespaces of the static
// origins, filtered to the Services named there, and every EndpointSlice in the
// watched namespace, where contracts can add upstreams at runtime.
func newEndpointCatalog(config *rest.Config, bindings upstreamBindings, watched string) (endpointCatalog, error) {
	client, err := discoveryclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	names := make(map[string]map[string]bool)
	origins := []string{bindings.Authz}
	for _, binding := range bindings.Services {
		origins = append(origins, binding.Origin, binding.DebugOrigin)
	}
	for _, route := range bindings.ServiceRoutes {
		origins = append(origins, route.Origin)
	}
	for _, origin := range origins {
		name, namespace := serviceReference(origin)
		if name == "" {
			continue
		}
		if names[namespace] == nil {
			names[namespace] = make(map[string]bool)
		}
		names[namespace][name] = true
	}
	out := make(endpointCatalog, len(names)+1)
	if watched != "" {
		out[watched] = newEndpointInformer(cache.NewListWatchFromClient(client.RESTClient(), "endpointslices", watched, fields.Everything()))
	}
	for namespace, services := range names {
		if namespace == watched {
			continue
		}
		selector := discoveryv1.LabelServiceName + " in ("
		var values []string
		for name := range services {
			values = append(values, name)
		}
		required, err := labels.Parse(selector + strings.Join(values, ",") + ")")
		if err != nil {
			return nil, err
		}
		api := cache.NewFilteredListWatchFromClient(client.RESTClient(), "endpointslices", namespace, func(options *metav1.ListOptions) {
			options.LabelSelector = required.String()
		})
		out[namespace] = newEndpointInformer(api)
	}
	return out, nil
}

func newEndpointInformer(api cache.ListerWatcher) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(api, &discoveryv1.EndpointSlice{}, 0, cache.Indexers{
		discoveryv1.LabelServiceName: func(object any) ([]string, error) {
			slice := object.(*discoveryv1.EndpointSlice)
			return []string{slice.Labels[discoveryv1.LabelServiceName]}, nil
		},
	})
}

func (c endpointCatalog) run(ctx context.Context) {
	for _, informer := range c {
		go informer.RunWithContext(ctx)
	}
}

func (c endpointCatalog) state(origin string) endpointState {
	if origin == "" {
		return endpointNotConfigured
	}
	name, namespace := serviceReference(origin)
	if name == "" {
		// Validated non-Service origins are loopback targets in local mode.
		return endpointLocal
	}
	informer := c[namespace]
	if informer == nil || !informer.HasSynced() {
		return endpointUnknown
	}
	slices, err := informer.GetIndexer().ByIndex(discoveryv1.LabelServiceName, name)
	if err != nil {
		return endpointUnknown
	}
	for _, item := range slices {
		for _, endpoint := range item.(*discoveryv1.EndpointSlice).Endpoints {
			condition := endpoint.Conditions
			if len(endpoint.Addresses) > 0 && (condition.Ready == nil || *condition.Ready) &&
				(condition.Terminating == nil || !*condition.Terminating) {
				return endpointReady
			}
		}
	}
	return endpointEmpty
}
