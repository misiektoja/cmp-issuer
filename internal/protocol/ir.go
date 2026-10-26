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
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// EnrollIR validates the requested key and executes one CRMF Initialization Request.
func (c *CMPClient) EnrollIR(ctx context.Context, request EnrollmentRequest) (EnrollmentResult, error) {
	request.Operation = OperationIR
	if err := ValidateIRRequest(request); err != nil {
		return EnrollmentResult{}, err
	}
	csr, _ := x509.ParseCertificateRequest(request.CSRDER)
	credentials, err := credentialsFor(request.Protection)
	if err != nil {
		return EnrollmentResult{}, permanent("configure protection", "badAlg", err)
	}
	message, requestDER, err := protectedIR(request, csr, credentials)
	if err != nil {
		return EnrollmentResult{}, err
	}
	httpClient := newHTTPClient(request)
	defer httpClient.CloseIdleConnections()
	responseDER, err := sendCMP(ctx, httpClient, request.EndpointURL, requestDER, request.MaxResponseSize, operationInitialization)
	if err != nil {
		return EnrollmentResult{}, err
	}
	response, err := pkicmp.ParsePKIMessage(responseDER)
	if err != nil {
		return EnrollmentResult{}, security("parse IP", "badDataFormat", err)
	}
	logCMPResponse(ctx, operationInitialization, response, len(responseDER))
	responseSigner, err := verifyResponse(message, response, request, nil, nil)
	if err != nil {
		return EnrollmentResult{}, err
	}
	return completeOrRefuse(ctx, httpClient, request, credentials, response, csr, responseSigner, message.Header.SenderNonce)
}

// ValidateIRRequest verifies the CSR and the key that proves possession without sending CMP traffic.
func ValidateIRRequest(request EnrollmentRequest) error {
	request.Operation = OperationIR
	if err := validateEnrollmentRequest(request); err != nil {
		return err
	}
	csr, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil {
		return permanent("parse CSR", "badRequest", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return permanent("verify CSR signature", "badPOP", err)
	}
	if request.RequestedPrivateKey == nil || !PublicKeysEqual(request.RequestedPrivateKey.Public(), csr.PublicKey) {
		return permanent("validate IR proof of possession", "badPOP", fmt.Errorf("requested private key does not match the CSR public key"))
	}
	return nil
}

// protectedIR builds an IR for the CSR identity with the configured protection.
func protectedIR(request EnrollmentRequest, csr *x509.CertificateRequest, credentials pkicmp.Credentials) (*pkicmp.PKIMessage, []byte, error) {
	// The CSR subject keeps its encoding. A CSR that names its subject only in subjectAltName carries
	// an empty name, which is the NULL-DN RFC 9483 section 4.1.1 requires in that case.
	template, err := certificateTemplate(request, csr, pkicmp.NewDirectoryNameFromRawDER(csr.RawSubject))
	if err != nil {
		return nil, nil, err
	}
	messageRequest := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertReqID: 0, CertTemplate: template}}
	if err := messageRequest.GeneratePOP(request.RequestedPrivateKey); err != nil {
		return nil, nil, permanent("generate IR proof of possession", "badPOP", err)
	}
	messages := pkicmp.CertReqMessages{messageRequest}
	message := pkicmp.NewPKIMessage(pkicmp.NewIRBody(&messages), pkicmp.MessageOptions{Sender: requestSender(request), Recipient: pkicmp.NewDirectoryName(request.Recipient), TransactionID: request.TransactionID})
	if request.Protection.Password != nil {
		message.Header.SenderKID = append([]byte(nil), request.Protection.Password.Reference...)
	}
	if request.ImplicitConfirm {
		message.Header.GeneralInfo = append(message.Header.GeneralInfo, pkicmp.ImplicitConfirmInfoValue())
	}
	if err := credentials.Protect(message); err != nil {
		return nil, nil, permanent("protect IR", "badAlg", err)
	}
	requestDER, err := message.MarshalBinary()
	if err != nil {
		return nil, nil, permanent("encode IR", "badDataFormat", err)
	}
	return message, requestDER, nil
}

// certificateTemplate builds the CRMF template of an IR or KUR from the subject, the requested key,
// the CSR extensions and the requested notAfter.
func certificateTemplate(request EnrollmentRequest, csr *x509.CertificateRequest, subject pkicmp.GeneralName) (pkicmp.CertTemplate, error) {
	publicKey, err := x509.MarshalPKIXPublicKey(request.RequestedPrivateKey.Public())
	if err != nil {
		return pkicmp.CertTemplate{}, permanent("encode requested public key", "badCertTemplate", err)
	}
	template := pkicmp.CertTemplate{Subject: subject, PublicKey: publicKey}
	if len(csr.Extensions) > 0 {
		extensions, err := asn1.Marshal(csr.Extensions)
		if err != nil {
			return pkicmp.CertTemplate{}, permanent("encode requested extensions", "badCertTemplate", err)
		}
		template.Extensions = extensions
	}
	if !request.RequestedNotAfter.IsZero() {
		template.Validity = &pkicmp.OptionalValidity{NotAfter: request.RequestedNotAfter}
	}
	return template, nil
}
