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

package protocol

import (
	"crypto/mldsa"
	"crypto/x509"
	"fmt"
)

// ValidateMLDSAKeyUsage enforces RFC 9881 section 5 for an ML-DSA subject public key.
func ValidateMLDSAKeyUsage(certificate *x509.Certificate) error {
	if certificate == nil {
		return fmt.Errorf("certificate is required")
	}
	if _, ok := certificate.PublicKey.(*mldsa.PublicKey); !ok || !certificateHasExtension(certificate, oidKeyUsage) {
		return nil
	}
	const allowed = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if certificate.KeyUsage == 0 {
		return fmt.Errorf("ML-DSA keyUsage extension must contain a signature usage")
	}
	if certificate.KeyUsage & ^allowed != 0 {
		return fmt.Errorf("ML-DSA keyUsage extension must not contain encipherment or key agreement usages")
	}
	return nil
}

// verifyCertificateChain selects a trusted chain whose ML-DSA keys satisfy RFC 9881.
func verifyCertificateChain(certificate *x509.Certificate, roots *x509.CertPool, intermediates *x509.CertPool) ([]*x509.Certificate, error) {
	chains, err := certificate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, err
	}
	var usageErr error
	for _, chain := range chains {
		usageErr = nil
		for _, certificate := range chain {
			if usageErr = ValidateMLDSAKeyUsage(certificate); usageErr != nil {
				break
			}
		}
		if usageErr == nil {
			return chain, nil
		}
	}
	if usageErr != nil {
		return nil, usageErr
	}
	return nil, fmt.Errorf("certificate verification returned no chain")
}
