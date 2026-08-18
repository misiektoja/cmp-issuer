//go:build e2e
// +build e2e

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

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/misiektoja/cmp-issuer/test/utils"
)

// certificateNameAnnotation is the annotation cert-manager sets on a CertificateRequest to name its Certificate.
const certificateNameAnnotation = "cert-manager.io/certificate-name"

// resourceCondition is the subset of a Kubernetes status condition that the specs assert on.
type resourceCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// conditionedResource decodes the status conditions of any resource that follows the conditions convention.
type conditionedResource struct {
	Status struct {
		Conditions []resourceCondition `json:"conditions"`
	} `json:"status"`
}

// kubectlApply creates or updates the resources of a manifest in the given namespace.
func kubectlApply(namespace string, manifest string) error {
	command := exec.Command("kubectl", "apply", "-n", namespace, "-f", "-")
	command.Stdin = strings.NewReader(manifest)
	_, err := utils.Run(command)
	return err
}

// secretData reads a Secret and returns its decoded entries.
func secretData(namespace string, name string) (map[string][]byte, error) {
	arguments := []string{"get", "secret", name, "-n", namespace, "-o", "json"}
	output, err := utils.Run(exec.Command("kubectl", arguments...))
	if err != nil {
		return nil, fmt.Errorf("read Secret %q: %w", name, err)
	}
	var decoded struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		return nil, fmt.Errorf("decode Secret %q: %w", name, err)
	}
	entries := make(map[string][]byte, len(decoded.Data))
	for key, value := range decoded.Data {
		material, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("decode Secret %q key %q: %w", name, key, err)
		}
		entries[key] = material
	}
	return entries, nil
}

// resourceExists reports whether a namespaced resource is present.
func resourceExists(kind string, namespace string, name string) bool {
	arguments := []string{"get", kind, name, "-n", namespace, "-o", "name"}
	_, err := utils.Run(exec.Command("kubectl", arguments...))
	return err == nil
}

// resourceConditions reads the status conditions of a namespaced resource.
func resourceConditions(kind string, namespace string, name string) ([]resourceCondition, error) {
	arguments := []string{"get", kind, name, "-n", namespace, "-o", "json"}
	output, err := utils.Run(exec.Command("kubectl", arguments...))
	if err != nil {
		return nil, fmt.Errorf("read %s %q: %w", kind, name, err)
	}
	var decoded conditionedResource
	if err := json.Unmarshal([]byte(output), &decoded); err != nil {
		return nil, fmt.Errorf("decode %s %q: %w", kind, name, err)
	}
	return decoded.Status.Conditions, nil
}

// findCondition returns the condition of the requested type or a zero value when it is absent.
func findCondition(conditions []resourceCondition, conditionType string) resourceCondition {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition
		}
	}
	return resourceCondition{}
}

// certificateRequestName returns the CertificateRequest that cert-manager created for a Certificate.
// cert-manager records the owning Certificate in an annotation rather than a label, so the requests are
// listed and filtered here instead of being selected by the API server.
func certificateRequestName(namespace string, certificate string) (string, error) {
	arguments := []string{"get", "certificaterequest", "-n", namespace, "-o", "json"}
	output, err := utils.Run(exec.Command("kubectl", arguments...))
	if err != nil {
		return "", fmt.Errorf("list CertificateRequests for %q: %w", certificate, err)
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name        string            `json:"name"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(output), &list); err != nil {
		return "", fmt.Errorf("decode CertificateRequests for %q: %w", certificate, err)
	}
	names := make([]string, 0, 1)
	for _, item := range list.Items {
		if item.Metadata.Annotations[certificateNameAnnotation] == certificate {
			names = append(names, item.Metadata.Name)
		}
	}
	if len(names) != 1 {
		return "", fmt.Errorf("expected one CertificateRequest for %q but found %d", certificate, len(names))
	}
	return names[0], nil
}

// setRequestCondition appends an approval decision to a CertificateRequest without dropping existing conditions.
func setRequestCondition(namespace string, name string, decision string, message string) error {
	conditions, err := resourceConditions("certificaterequest", namespace, name)
	if err != nil {
		return err
	}
	updated := make([]map[string]string, 0, len(conditions)+1)
	for _, condition := range conditions {
		if condition.Type == decision {
			return nil
		}
		updated = append(updated, map[string]string{
			"type": condition.Type, "status": condition.Status,
			"reason": condition.Reason, "message": condition.Message,
		})
	}
	updated = append(updated, map[string]string{
		"type": decision, "status": "True", "reason": "E2E", "message": message,
		"lastTransitionTime": time.Now().UTC().Format(time.RFC3339),
	})
	payload, err := json.Marshal(map[string]any{"status": map[string]any{"conditions": updated}})
	if err != nil {
		return fmt.Errorf("encode %s patch: %w", decision, err)
	}
	arguments := []string{
		"patch", "certificaterequest", name, "-n", namespace,
		"--subresource=status", "--type=merge", "-p", string(payload),
	}
	if _, err := utils.Run(exec.Command("kubectl", arguments...)); err != nil {
		return fmt.Errorf("apply %s decision to %q: %w", decision, name, err)
	}
	return nil
}

// issuedCertificate returns the certificate that a signer stored on a CertificateRequest.
func issuedCertificate(namespace string, request string) ([]byte, error) {
	arguments := []string{
		"get", "certificaterequest", request, "-n", namespace,
		"-o", "jsonpath={.status.certificate}",
	}
	output, err := utils.Run(exec.Command("kubectl", arguments...))
	if err != nil {
		return nil, fmt.Errorf("read issued certificate of %q: %w", request, err)
	}
	material, err := base64.StdEncoding.DecodeString(strings.TrimSpace(output))
	if err != nil {
		return nil, fmt.Errorf("decode issued certificate of %q: %w", request, err)
	}
	return material, nil
}

// serviceAccountCanRead reports whether the controller identity may read Secrets in a namespace.
func serviceAccountCanRead(namespace string, serviceAccount string, resource string) (bool, error) {
	arguments := []string{
		"auth", "can-i", "get", resource, "-n", namespace, "--as", serviceAccount,
	}
	output, err := utils.Run(exec.Command("kubectl", arguments...))
	if err != nil && !strings.Contains(output, "no") {
		return false, fmt.Errorf("evaluate access to %q: %w", resource, err)
	}
	return strings.HasPrefix(strings.TrimSpace(output), "yes"), nil
}
