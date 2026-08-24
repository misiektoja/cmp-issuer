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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/misiektoja/go-pkicmp-ng/pkicmp"
)

var (
	oidKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// EnrollKUR validates both key proofs and executes one certificate-authenticated Key Update Request.
func (c *CMPClient) EnrollKUR(ctx context.Context, request EnrollmentRequest) (EnrollmentResult, error) {
	request.Operation = OperationKUR
	if err := ValidateKURRequest(request); err != nil {
		return EnrollmentResult{}, err
	}
	csr, _ := x509.ParseCertificateRequest(request.CSRDER)
	credentials, err := credentialsFor(request.Protection)
	if err != nil {
		return EnrollmentResult{}, permanent("configure KUR protection", "badAlg", err)
	}
	message, requestDER, err := protectedKUR(request, csr, credentials)
	if err != nil {
		return EnrollmentResult{}, err
	}
	httpClient := newHTTPClient(request)
	defer httpClient.CloseIdleConnections()
	responseDER, err := sendCMP(ctx, httpClient, request.EndpointURL, requestDER, request.MaxResponseSize, operationKeyUpdate)
	if err != nil {
		return EnrollmentResult{}, err
	}
	response, err := pkicmp.ParsePKIMessage(responseDER)
	if err != nil {
		return EnrollmentResult{}, security("parse KUP", "badDataFormat", err)
	}
	logCMPResponse(ctx, operationKeyUpdate, response, len(responseDER))
	responseSigner, err := verifyResponse(message, response, request, nil, nil)
	if err != nil {
		return EnrollmentResult{}, err
	}
	return finishTransaction(request, response, csr, responseSigner, message.Header.SenderNonce)
}

// ValidateKURRequest verifies both key proofs and the unchanged certificate identity without sending CMP traffic.
func ValidateKURRequest(request EnrollmentRequest) error {
	request.Operation = OperationKUR
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
	return validateKURProofs(request, csr, time.Now())
}

// protectedKUR builds CRMF proof of possession and protects the message with the certificate being updated.
func protectedKUR(request EnrollmentRequest, csr *x509.CertificateRequest, credentials pkicmp.Credentials) (*pkicmp.PKIMessage, []byte, error) {
	publicKey, err := x509.MarshalPKIXPublicKey(request.RequestedPrivateKey.Public())
	if err != nil {
		return nil, nil, permanent("encode requested public key", "badCertTemplate", err)
	}
	extensions, err := asn1.Marshal(csr.Extensions)
	if err != nil {
		return nil, nil, permanent("encode requested extensions", "badCertTemplate", err)
	}
	template := pkicmp.CertTemplate{Subject: pkicmp.NewDirectoryName(csr.Subject), PublicKey: publicKey}
	if len(csr.Extensions) > 0 {
		template.Extensions = extensions
	}
	messageRequest := pkicmp.CertReqMsg{CertReq: pkicmp.CertRequest{CertReqID: 0, CertTemplate: template}}
	if err := messageRequest.GeneratePOP(request.RequestedPrivateKey); err != nil {
		return nil, nil, permanent("generate KUR proof of possession", "badPOP", err)
	}
	messages := pkicmp.CertReqMessages{messageRequest}
	sender := pkicmp.NewDirectoryName(request.Protection.Signature.Certificate.Subject)
	message := pkicmp.NewPKIMessage(pkicmp.NewKURBody(&messages), pkicmp.MessageOptions{Sender: sender, Recipient: pkicmp.NewDirectoryName(request.Recipient), TransactionID: request.TransactionID})
	if request.ImplicitConfirm {
		message.Header.GeneralInfo = append(message.Header.GeneralInfo, pkicmp.ImplicitConfirmInfoValue())
	}
	if err := credentials.Protect(message); err != nil {
		return nil, nil, permanent("protect KUR", "badAlg", err)
	}
	requestDER, err := message.MarshalBinary()
	if err != nil {
		return nil, nil, permanent("encode KUR", "badDataFormat", err)
	}
	return message, requestDER, nil
}

// validateKURProofs enforces the existing-certificate and requested-key invariants before any network send.
func validateKURProofs(request EnrollmentRequest, csr *x509.CertificateRequest, now time.Time) error {
	if request.Protection.Password != nil || request.Protection.Signature == nil {
		return permanent("validate KUR protection", "badRequest", fmt.Errorf("KUR requires signature protection with the certificate being updated"))
	}
	if request.RequestedPrivateKey == nil || !PublicKeysEqual(request.RequestedPrivateKey.Public(), csr.PublicKey) {
		return permanent("validate KUR proof of possession", "badPOP", fmt.Errorf("requested private key does not match the CSR public key"))
	}
	certificate := request.Protection.Signature.Certificate
	if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return permanent("validate KUR protection certificate", "badTime", fmt.Errorf("certificate being updated is not currently valid"))
	}
	if certificateHasExtension(certificate, oidKeyUsage) && certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return permanent("validate KUR protection certificate", "badAlg", fmt.Errorf("certificate being updated does not permit digital signatures"))
	}
	if !sameKURIdentity(certificate, csr) {
		return permanent("validate KUR certificate identity", "badCertTemplate", fmt.Errorf("CSR subject or subject alternative names differ from the certificate being updated"))
	}
	return nil
}

// sameKURIdentity compares subject attributes and every encoded GeneralName without depending on ordering.
func sameKURIdentity(certificate *x509.Certificate, csr *x509.CertificateRequest) bool {
	certificateSubject, certificateErr := rawAttributeSet(certificate.RawSubject)
	requestSubject, requestErr := rawAttributeSet(csr.RawSubject)
	if certificateErr != nil || requestErr != nil || !slices.Equal(certificateSubject, requestSubject) {
		return false
	}
	certificateNames, certificateErr := generalNameSet(certificate.Extensions)
	requestNames, requestErr := generalNameSet(csr.Extensions)
	return certificateErr == nil && requestErr == nil && slices.Equal(certificateNames, requestNames)
}

// rawAttributeSet parses and sorts a distinguished name into its exact attribute entries.
func rawAttributeSet(raw []byte) ([]string, error) {
	var sequence pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &sequence); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("parse distinguished name")
	}
	return attributeSet(sequence), nil
}

// generalNameSet returns sorted DER encodings of every subject alternative name entry.
func generalNameSet(extensions []pkix.Extension) ([]string, error) {
	for _, extension := range extensions {
		if !extension.Id.Equal(oidSubjectAltName) {
			continue
		}
		var names []asn1.RawValue
		if rest, err := asn1.Unmarshal(extension.Value, &names); err != nil || len(rest) != 0 {
			return nil, fmt.Errorf("parse subject alternative names")
		}
		encoded := make([]string, 0, len(names))
		for _, name := range names {
			encoded = append(encoded, hex.EncodeToString(name.FullBytes))
		}
		slices.Sort(encoded)
		return encoded, nil
	}
	return nil, nil
}

// certificateHasExtension reports whether a certificate explicitly carries one extension.
func certificateHasExtension(certificate *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oid) {
			return true
		}
	}
	return false
}
