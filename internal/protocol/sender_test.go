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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"testing"

	"github.com/misiektoja/go-pki-cmp/pkicmp"
)

// reorderedSubject returns a subject DER that encoding a pkix.Name cannot reproduce, with commonName
// ahead of organizationName and UTF8String values, and a pkix.Name with the same attributes.
func reorderedSubject(t *testing.T, commonName string) ([]byte, pkix.Name) {
	t.Helper()
	utf8 := func(oid asn1.ObjectIdentifier, value string) pkix.RelativeDistinguishedNameSET {
		return pkix.RelativeDistinguishedNameSET{{Type: oid, Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(value)}}}
	}
	der, err := asn1.Marshal(pkix.RDNSequence{
		utf8(asn1.ObjectIdentifier{2, 5, 4, 3}, commonName),
		utf8(asn1.ObjectIdentifier{2, 5, 4, 10}, "Example Org"),
	})
	if err != nil {
		t.Fatal(err)
	}
	name := pkix.Name{CommonName: commonName, Organization: []string{"Example Org"}}
	if encoded, err := asn1.Marshal(pkicmp.NewDirectoryName(name).DirectoryName); err != nil || bytes.Equal(encoded, der) {
		t.Fatalf("expected the subject to differ from an encoded pkix.Name: %v", err)
	}
	return der, name
}

// certificateWithRawSubject issues a certificate for key whose subject is rawSubject, or empty when rawSubject is nil.
func certificateWithRawSubject(t *testing.T, pki testPKI, rawSubject []byte, key crypto.Signer) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		RawSubject:   rawSubject,
		DNSNames:     []string{"subject.example.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	// KUR tests update this certificate, so it carries the validity of a certificate being updated.
	template.NotBefore, template.NotAfter = currentCertificateValidity()
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, pki.CACertificate, key.Public(), pki.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

// directoryNameContent returns the Name DER inside an encoded directoryName GeneralName.
func directoryNameContent(t *testing.T, name pkicmp.GeneralName) []byte {
	t.Helper()
	var value asn1.RawValue
	if rest, err := asn1.Unmarshal(name.Raw, &value); err != nil || len(rest) != 0 || value.Class != asn1.ClassContextSpecific || value.Tag != 4 || !value.IsCompound {
		t.Fatalf("expected an encoded directoryName, got %x", name.Raw)
	}
	return value.Bytes
}

// TestRequestSender verifies the sender precedence and that a signature sender repeats the certificate subject encoding.
func TestRequestSender(t *testing.T) {
	pki := newTestPKI(t)
	rawSubject, _ := reorderedSubject(t, "cmp-issuer-signer")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := &SignatureProtection{PrivateKey: key, Certificate: certificateWithRawSubject(t, pki, rawSubject, key), Chain: []*x509.Certificate{pki.CACertificate}}
	configured := pkix.Name{CommonName: "configured-sender"}

	request := baseEnrollmentRequest(t, pki, "https://cmp.example.test")
	request.Protection.Signature = signature
	if content := directoryNameContent(t, requestSender(request)); !bytes.Equal(content, rawSubject) {
		t.Fatalf("expected the certificate subject %x as sender, got %x", rawSubject, content)
	}

	request.Sender = &configured
	if sender := requestSender(request); len(sender.Raw) != 0 || !slices.Equal(attributeSet(sender.DirectoryName), attributeSet(pkicmp.NewDirectoryName(configured).DirectoryName)) {
		t.Fatalf("expected the configured sender, got %+v", sender)
	}

	request = baseEnrollmentRequest(t, pki, "https://cmp.example.test")
	request.Protection.Password = &PasswordProtection{Reference: []byte("reference"), Secret: []byte("secret")}
	if sender := requestSender(request); len(sender.Raw) != 0 || len(sender.DirectoryName) != 0 {
		t.Fatalf("expected an empty sender for MAC protection without a configured sender, got %+v", sender)
	}
}

// TestProtectedEnrollmentSendsCertificateSubject verifies a signature-protected P10CR carries the protection
// certificate subject unmodified, as RFC 9483 section 3.1 requires.
func TestProtectedEnrollmentSendsCertificateSubject(t *testing.T) {
	pki := newTestPKI(t)
	rawSubject, _ := reorderedSubject(t, "cmp-issuer-signer")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := baseEnrollmentRequest(t, pki, "https://cmp.example.test")
	request.Protection.Signature = &SignatureProtection{PrivateKey: key, Certificate: certificateWithRawSubject(t, pki, rawSubject, key), Chain: []*x509.Certificate{pki.CACertificate}}
	csr, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := credentialsFor(request.Protection)
	if err != nil {
		t.Fatal(err)
	}
	_, encoded, err := protectedEnrollment(request, csr, credentials)
	if err != nil {
		t.Fatal(err)
	}
	message, err := pkicmp.ParsePKIMessage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if content := directoryNameContent(t, message.Header.Sender); !bytes.Equal(content, rawSubject) {
		t.Fatalf("expected the certificate subject %x as sender, got %x", rawSubject, content)
	}
}
