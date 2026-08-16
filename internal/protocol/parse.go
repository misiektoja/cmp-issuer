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

package protocol

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	oidUserID          = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	oidEmailAddress    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

// ParseDistinguishedName parses the supported RFC 4514 attribute subset without accepting empty values.
func ParseDistinguishedName(value string) (pkix.Name, error) {
	parts, err := splitDN(value)
	if err != nil {
		return pkix.Name{}, err
	}
	name := pkix.Name{}
	for _, part := range parts {
		key, raw, found := strings.Cut(part, "=")
		if !found {
			return pkix.Name{}, fmt.Errorf("distinguished name component lacks '='")
		}
		decoded, err := unescapeDNValue(strings.TrimSpace(raw))
		if err != nil {
			return pkix.Name{}, err
		}
		if decoded == "" {
			return pkix.Name{}, fmt.Errorf("distinguished name value is empty")
		}
		if err := addNameAttribute(&name, strings.ToUpper(strings.TrimSpace(key)), decoded); err != nil {
			return pkix.Name{}, err
		}
	}
	return name, nil
}

// splitDN separates unescaped comma-delimited distinguished name components.
func splitDN(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("distinguished name is empty")
	}
	parts := make([]string, 0, 4)
	start := 0
	escaped := false
	for index, character := range value {
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == ',' {
			parts = append(parts, strings.TrimSpace(value[start:index]))
			start = index + 1
		}
	}
	if escaped {
		return nil, fmt.Errorf("distinguished name ends with an escape")
	}
	parts = append(parts, strings.TrimSpace(value[start:]))
	if slices.Contains(parts, "") {
		return nil, fmt.Errorf("distinguished name contains an empty component")
	}
	return parts, nil
}

// unescapeDNValue decodes RFC 4514 single-character escapes used by configured names.
func unescapeDNValue(value string) (string, error) {
	var result strings.Builder
	escaped := false
	for _, character := range value {
		if escaped {
			result.WriteRune(character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		result.WriteRune(character)
	}
	if escaped {
		return "", fmt.Errorf("distinguished name value ends with an escape")
	}
	return result.String(), nil
}

// addNameAttribute appends one supported distinguished name attribute.
func addNameAttribute(name *pkix.Name, key string, value string) error {
	switch key {
	case "CN":
		name.CommonName = value
	case "C":
		name.Country = append(name.Country, value)
	case "L":
		name.Locality = append(name.Locality, value)
	case "ST":
		name.Province = append(name.Province, value)
	case "STREET":
		name.StreetAddress = append(name.StreetAddress, value)
	case "O":
		name.Organization = append(name.Organization, value)
	case "OU":
		name.OrganizationalUnit = append(name.OrganizationalUnit, value)
	case "SERIALNUMBER":
		name.SerialNumber = value
	case "DC":
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{Type: oidDomainComponent, Value: value})
	case "UID":
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{Type: oidUserID, Value: value})
	case "EMAILADDRESS", "E":
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{Type: oidEmailAddress, Value: value})
	default:
		return fmt.Errorf("unsupported distinguished name attribute %q", key)
	}
	return nil
}

// ParseCertificates parses one DER certificate or one or more PEM certificates.
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	remaining := data
	certificates := make([]*x509.Certificate, 0, 2)
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM certificate: %w", err)
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) > 0 {
		if len(strings.TrimSpace(string(remaining))) != 0 {
			return nil, fmt.Errorf("certificate bundle contains trailing non-PEM data")
		}
		return certificates, nil
	}
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}
	return []*x509.Certificate{certificate}, nil
}

// ParseCertificateRequestDER accepts one PEM or DER CSR and returns its unchanged DER encoding.
func ParseCertificateRequestDER(data []byte) ([]byte, error) {
	requestDER := data
	if block, rest := pem.Decode(data); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("PEM block is not a certificate request")
		}
		if len(strings.TrimSpace(string(rest))) != 0 {
			return nil, fmt.Errorf("certificate request contains trailing data")
		}
		requestDER = block.Bytes
	}
	request, err := x509.ParseCertificateRequest(requestDER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate request: %w", err)
	}
	if err := request.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify certificate request signature: %w", err)
	}
	return append([]byte(nil), request.Raw...), nil
}

// ParseSigner parses an unencrypted PEM or DER PKCS #1, SEC 1 or PKCS #8 private key.
func ParseSigner(data []byte) (crypto.Signer, error) {
	keyDER := data
	if block, rest := pem.Decode(data); block != nil {
		if len(strings.TrimSpace(string(rest))) != 0 {
			return nil, fmt.Errorf("private key contains trailing data")
		}
		keyDER = block.Bytes
	}
	parsers := []func([]byte) (any, error){x509.ParsePKCS8PrivateKey, func(value []byte) (any, error) { return x509.ParsePKCS1PrivateKey(value) }, func(value []byte) (any, error) { return x509.ParseECPrivateKey(value) }}
	var parseErrors []error
	for _, parser := range parsers {
		parsed, err := parser(keyDER)
		if err != nil {
			parseErrors = append(parseErrors, err)
			continue
		}
		signer, ok := parsed.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key type does not implement crypto.Signer")
		}
		return signer, nil
	}
	return nil, fmt.Errorf("parse private key: %w", errors.Join(parseErrors...))
}

// PublicKeysEqual compares public keys through their canonical SubjectPublicKeyInfo encodings.
func PublicKeysEqual(first any, second any) bool {
	firstDER, firstErr := x509.MarshalPKIXPublicKey(first)
	secondDER, secondErr := x509.MarshalPKIXPublicKey(second)
	return firstErr == nil && secondErr == nil && subtle.ConstantTimeCompare(firstDER, secondDER) == 1
}

// ValidateSignerCertificate verifies that a private key matches its certificate.
func ValidateSignerCertificate(signer crypto.Signer, certificate *x509.Certificate) error {
	if signer == nil || certificate == nil {
		return fmt.Errorf("signer and certificate are required")
	}
	if !PublicKeysEqual(signer.Public(), certificate.PublicKey) {
		return fmt.Errorf("private key does not match certificate public key")
	}
	return nil
}
