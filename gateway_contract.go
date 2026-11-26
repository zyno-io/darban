package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"unicode/utf8"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	maxInlineOpenAPI  = 1_400_000
	maxDecodedOpenAPI = 16 << 20
)

type gatewayContractSpec struct {
	ServiceName       string               `json:"serviceName"`
	Upstream          string               `json:"upstream,omitempty"`
	Prefix            string               `json:"prefix,omitempty"`
	DefaultVisibility *operationVisibility `json:"defaultVisibility,omitempty"`
	OpenAPI           gatewayOpenAPI       `json:"openapi"`
	Rewrites          []rewriteRule        `json:"rewrites"`
}

type gatewayOpenAPI struct {
	YAML       *string `json:"yaml,omitempty"`
	GzipBase64 *string `json:"gzipBase64,omitempty"`
	SHA256     string  `json:"sha256"`
}

func newGatewayContractInformer(config *rest.Config, namespace, apiGroup string) (cache.SharedIndexInformer, error) {
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	gatewayContracts := schema.GroupVersionResource{Group: apiGroup, Version: "v1alpha1", Resource: "gatewaycontracts"}
	contracts := client.Resource(gatewayContracts).Namespace(namespace)
	api := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
			return contracts.List(ctx, options)
		},
		WatchFuncWithContext: contracts.Watch,
	}
	object := &unstructured.Unstructured{}
	object.SetGroupVersionKind(gatewayContracts.GroupVersion().WithKind("GatewayContract"))
	return cache.NewSharedIndexInformer(api, object, 0, cache.Indexers{}), nil
}

func decodeGzipOpenAPI(encoded string) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > maxInlineOpenAPI || strings.ContainsAny(encoded, "\r\n") {
		return nil, errors.New("invalid encoded OpenAPI size or format")
	}
	compressed := base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(encoded))
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, errors.New("invalid gzip OpenAPI")
	}
	defer reader.Close()
	yaml, err := io.ReadAll(io.LimitReader(reader, maxDecodedOpenAPI+1))
	if err != nil || len(yaml) > maxDecodedOpenAPI {
		return nil, errors.New("invalid decoded OpenAPI size or format")
	}
	return yaml, nil
}

func decodeOpenAPI(input gatewayOpenAPI) ([]byte, error) {
	if (input.YAML == nil) == (input.GzipBase64 == nil) {
		return nil, errors.New("exactly one of openapi.yaml or openapi.gzipBase64 is required")
	}
	var yaml []byte
	if input.YAML != nil {
		if len(*input.YAML) > maxInlineOpenAPI {
			return nil, errors.New("plain OpenAPI exceeds the inline size limit")
		}
		yaml = []byte(*input.YAML)
	} else {
		decoded, err := decodeGzipOpenAPI(*input.GzipBase64)
		if err != nil {
			return nil, err
		}
		yaml = decoded
	}
	if len(yaml) == 0 || !utf8.Valid(yaml) {
		return nil, errors.New("OpenAPI must be nonempty UTF-8")
	}
	digest := sha256.Sum256(yaml)
	if hex.EncodeToString(digest[:]) != input.SHA256 {
		return nil, errors.New("OpenAPI checksum mismatch")
	}
	return yaml, nil
}

func decodeGatewayContract(object *unstructured.Unstructured) (registration, error) {
	data, found, err := unstructured.NestedMap(object.Object, "spec")
	if err != nil || !found {
		return registration{}, errors.New("spec is required")
	}
	var spec gatewayContractSpec
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(data, &spec); err != nil {
		return registration{}, errors.New("invalid contract spec")
	}
	if !serviceName.MatchString(spec.ServiceName) || object.GetName() != contractNamePrefix+spec.ServiceName || spec.Rewrites == nil {
		return registration{}, errors.New("invalid service registration name or rewrites list")
	}
	openAPI, err := decodeOpenAPI(spec.OpenAPI)
	if err != nil {
		return registration{}, err
	}
	rewrites, err := json.Marshal(spec.Rewrites)
	if err != nil {
		return registration{}, err
	}
	return registration{
		serviceName: spec.ServiceName, openAPI: string(openAPI), rewrites: string(rewrites),
		upstream: spec.Upstream, prefix: spec.Prefix, namespace: object.GetNamespace(),
		defaultVisibility: spec.DefaultVisibility, created: object.GetCreationTimestamp().Time,
	}, nil
}

func loadClusterRegistrations(current cache.Store) ([]registration, error) {
	registrations := make(map[string]registration)
	for _, item := range current.List() {
		object := item.(*unstructured.Unstructured)
		reg, err := decodeGatewayContract(object)
		if err != nil {
			// A broken contract rejects its own service and takes its slot.
			invalid := fmt.Errorf("GatewayContract %s: %w", object.GetName(), err)
			name, ok := nameFromResource(object.GetName())
			if !ok {
				// No service to attribute it to, so skip it rather than block the rest.
				log.Printf("contract candidate rejected: %v", invalid)
				continue
			}
			reg = registration{serviceName: name, invalid: invalid}
		}
		registrations[reg.serviceName] = reg
	}
	result := make([]registration, 0, len(registrations))
	for _, reg := range registrations {
		result = append(result, reg)
	}
	return result, nil
}

// loadContractList reads a GatewayContract list, such as the output of
// kubectl get gatewaycontracts -o json, and decodes it exactly as cluster mode
// decodes its informer's store.
func loadContractList(path string) ([]registration, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if list.Items == nil {
		return nil, fmt.Errorf("%s: expected a list with items", path)
	}
	// Cluster mode watches one namespace, where each name is one service.
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	namespace, names := "", make(map[string]bool, len(list.Items))
	for i, item := range list.Items {
		object := &unstructured.Unstructured{Object: item}
		if kind := object.GetKind(); kind != "" && kind != "GatewayContract" {
			return nil, fmt.Errorf("%s: unexpected %s %s", path, kind, object.GetName())
		}
		if i == 0 {
			namespace = object.GetNamespace()
		}
		if object.GetNamespace() != namespace {
			return nil, fmt.Errorf("%s: contracts from namespaces %q and %q; list one namespace", path, namespace, object.GetNamespace())
		}
		if names[object.GetName()] {
			return nil, fmt.Errorf("%s: %s is listed twice", path, object.GetName())
		}
		names[object.GetName()] = true
		if err := store.Add(object); err != nil {
			return nil, err
		}
	}
	return loadClusterRegistrations(store)
}
