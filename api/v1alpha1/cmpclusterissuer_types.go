/*
Copyright 2026 The cmp-issuer Authors.

SPDX-License-Identifier: GPL-3.0-only

This file is part of cmp-issuer.

cmp-issuer is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, version 3.

cmp-issuer is distributed in the hope that it will be useful but WITHOUT ANY
WARRANTY. See the GNU General Public License for more details.
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
