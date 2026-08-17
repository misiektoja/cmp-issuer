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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`

// CMPClusterIssuer is the Schema for the cmpclusterissuers API
type CMPClusterIssuer struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of CMPClusterIssuer
	// +required
	Spec CMPIssuerSpec `json:"spec"`

	// status defines the observed state of CMPClusterIssuer
	// +optional
	Status CMPIssuerStatus `json:"status,omitzero"`
}

// GetConditions returns the cluster issuer status conditions for issuer-lib.
func (i *CMPClusterIssuer) GetConditions() []metav1.Condition { return i.Status.Conditions }

// GetIssuerTypeIdentifier returns the cert-manager cluster issuer type identifier.
func (i *CMPClusterIssuer) GetIssuerTypeIdentifier() string {
	return "cmpclusterissuers.certmanager.misiektoja.github.io"
}

// +kubebuilder:object:root=true

// CMPClusterIssuerList contains a list of CMPClusterIssuer
type CMPClusterIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []CMPClusterIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &CMPClusterIssuer{}, &CMPClusterIssuerList{})
		return nil
	})
}
