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
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`

// CMPIssuer is the Schema for the cmpissuers API
type CMPIssuer struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of CMPIssuer
	// +required
	Spec CMPIssuerSpec `json:"spec"`

	// status defines the observed state of CMPIssuer
	// +optional
	Status CMPIssuerStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// CMPIssuerList contains a list of CMPIssuer
type CMPIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []CMPIssuer `json:"items"`
}

// GetConditions returns the issuer status conditions for issuer-lib.
func (i *CMPIssuer) GetConditions() []metav1.Condition { return i.Status.Conditions }

// GetIssuerTypeIdentifier returns the cert-manager issuer type identifier.
func (i *CMPIssuer) GetIssuerTypeIdentifier() string {
	return "cmpissuers.certmanager.misiektoja.github.io"
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &CMPIssuer{}, &CMPIssuerList{})
		return nil
	})
}
