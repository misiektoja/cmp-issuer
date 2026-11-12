//go:build e2e

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

const (
	// kubectlGet is the kubectl verb that reads resources.
	kubectlGet = "get"
	// conditionTrue is the status of a condition that holds.
	conditionTrue = "True"
	// caCertificateKey is the Secret key that holds PEM trust anchors.
	caCertificateKey = "ca.crt"
	// certificateRequestResource and cmpTransactionResource name resource kinds for kubectl.
	certificateRequestResource = "certificaterequest"
	cmpTransactionResource     = "cmptransaction"
	// operationP10CR, operationIR and operationKUR name CMP operations in issuer specs and transaction records.
	operationP10CR = "P10CR"
	operationIR    = "IR"
	operationKUR   = "KUR"
	// kubectlJSON is the kubectl output format that the helpers decode.
	kubectlJSON = "json"
)

// resourceCondition is the subset of a Kubernetes status condition that the specs assert on.
type resourceCondition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// conditionPatch is a status condition as a merge patch writes it.
type conditionPatch struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
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
	arguments := []string{kubectlGet, "secret", name, "-n", namespace, "-o", kubectlJSON}
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
	arguments := []string{kubectlGet, kind, name, "-n", namespace, "-o", "name"}
	_, err := utils.Run(exec.Command("kubectl", arguments...))
	return err == nil
}

// resourceConditions reads the status conditions of a namespaced resource.
func resourceConditions(kind string, namespace string, name string) ([]resourceCondition, error) {
	arguments := []string{kubectlGet, kind, name, "-n", namespace, "-o", kubectlJSON}
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
	arguments := []string{kubectlGet, certificateRequestResource, "-n", namespace, "-o", kubectlJSON}
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

// opposingDecision returns the approval decision that cannot coexist with the given one.
func opposingDecision(decision string) string {
	if decision == "Denied" {
		return "Approved"
	}
	return "Denied"
}

// setRequestCondition appends an approval decision to a CertificateRequest without dropping existing conditions.
func setRequestCondition(namespace string, name string, decision string, message string) error {
	conditions, err := resourceConditions(certificateRequestResource, namespace, name)
	if err != nil {
		return err
	}
	updated := make([]conditionPatch, 0, len(conditions)+1)
	for _, condition := range conditions {
		if condition.Type == decision {
			return nil
		}
		// cert-manager refuses a status that carries both decisions, so report the cause here rather
		// than letting the admission webhook reject the patch for a reason that reads like a defect.
		if condition.Type == opposingDecision(decision) && condition.Status == conditionTrue {
			return fmt.Errorf("cannot record %s on %q: it already carries %s", decision, name, condition.Type)
		}
		updated = append(updated, conditionPatch{
			Type: condition.Type, Status: condition.Status,
			Reason: condition.Reason, Message: condition.Message,
		})
	}
	updated = append(updated, conditionPatch{
		Type: decision, Status: conditionTrue, Reason: "E2E", Message: message,
		LastTransitionTime: time.Now().UTC().Format(time.RFC3339),
	})
	payload, err := json.Marshal(map[string]any{"status": map[string]any{"conditions": updated}})
	if err != nil {
		return fmt.Errorf("encode %s patch: %w", decision, err)
	}
	arguments := []string{
		"patch", certificateRequestResource, name, "-n", namespace,
		"--subresource=status", "--type=merge", "-p", string(payload),
	}
	if _, err := utils.Run(exec.Command("kubectl", arguments...)); err != nil {
		// cert-manager's own approver holds approval permission for the auto-approved issuers, so it
		// can record the same decision between the read above and this patch. The webhook then refuses
		// to let the decision be modified, which is the outcome the caller wanted rather than a
		// failure, so the conditions are read again before the error is reported.
		if recorded, readErr := hasRequestDecision(namespace, name, decision); readErr == nil && recorded {
			return nil
		}
		return fmt.Errorf("apply %s decision to %q: %w", decision, name, err)
	}
	return nil
}

// hasRequestDecision reports whether a CertificateRequest already carries the given approval decision.
func hasRequestDecision(namespace string, name string, decision string) (bool, error) {
	conditions, err := resourceConditions(certificateRequestResource, namespace, name)
	if err != nil {
		return false, err
	}
	for _, condition := range conditions {
		if condition.Type == decision && condition.Status == conditionTrue {
			return true, nil
		}
	}
	return false, nil
}

// issuedCertificate returns the certificate that a signer stored on a CertificateRequest.
func issuedCertificate(namespace string, request string) ([]byte, error) {
	arguments := []string{
		kubectlGet, certificateRequestResource, request, "-n", namespace,
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
