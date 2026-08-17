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

package controller

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	issuersigner "github.com/cert-manager/issuer-lib/controllers/signer"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cmpv1alpha1 "github.com/misiektoja/cmp-issuer/api/v1alpha1"
	"github.com/misiektoja/cmp-issuer/internal/logging"
	"github.com/misiektoja/cmp-issuer/internal/protocol"
)

const (
	// confirmationExplicit reports an enrollment completed by certConf and pkiConf.
	confirmationExplicit = "Explicit"
	// confirmationImplicit reports an enrollment the server granted implicit confirmation for.
	confirmationImplicit = "Implicit"
	// unknownKeyType names a public key algorithm this release does not describe.
	unknownKeyType = "Unknown"
)

// issuerLogValue names the issuer serving a transaction as one greppable value.
func issuerLogValue(issuer issuerapi.Issuer) string {
	if _, isCluster := issuer.(*cmpv1alpha1.CMPClusterIssuer); isCluster {
		return "CMPClusterIssuer/" + issuer.GetName()
	}
	return "CMPIssuer/" + issuer.GetNamespace() + "/" + issuer.GetName()
}

// transactionIDLogValue renders a CMP transaction identifier the way CMP servers report it.
func transactionIDLogValue(transactionID []byte) string { return hex.EncodeToString(transactionID) }

// timestampLogValue renders a point in time in the format the rest of the log uses.
func timestampLogValue(moment time.Time) string { return moment.UTC().Format(time.RFC3339) }

// durationLogValue renders an elapsed time without spurious sub-millisecond precision.
func durationLogValue(elapsed time.Duration) string { return elapsed.Round(time.Millisecond).String() }

// certificateLogValues describes an issued chain with the detail needed to identify a certificate without reading its Secret.
func certificateLogValues(chain []*x509.Certificate) []any {
	if len(chain) == 0 {
		return nil
	}
	leaf := chain[0]
	keyType, keySize := publicKeyDescription(leaf.PublicKey)
	return append([]any{
		"subject", logging.Text(leaf.Subject.String()),
		"serialNumber", serialNumberLogValue(leaf),
		"notBefore", timestampLogValue(leaf.NotBefore),
		"notAfter", timestampLogValue(leaf.NotAfter),
		"issuingCA", logging.Text(leaf.Issuer.String()),
		"keyType", keyType,
		"keySize", keySize,
		"signatureAlgorithm", leaf.SignatureAlgorithm.String(),
		"chainLength", len(chain),
	}, subjectAlternativeNameLogValues(leaf)...)
}

// serialNumberLogValue renders a certificate serial number as the hexadecimal form certificate tools print.
func serialNumberLogValue(certificate *x509.Certificate) string {
	if certificate.SerialNumber == nil {
		return ""
	}
	return certificate.SerialNumber.Text(16)
}

// subjectAlternativeNameLogValues renders the bounded subject alternative names an issued certificate carries.
func subjectAlternativeNameLogValues(certificate *x509.Certificate) []any {
	values := []any{}
	if names := logging.List(certificate.DNSNames); len(names) > 0 {
		values = append(values, "dnsNames", names)
	}
	if addresses := certificate.IPAddresses; len(addresses) > 0 {
		rendered := make([]string, 0, len(addresses))
		for _, address := range addresses {
			rendered = append(rendered, address.String())
		}
		values = append(values, "ipAddresses", logging.List(rendered))
	}
	if uris := certificate.URIs; len(uris) > 0 {
		rendered := make([]string, 0, len(uris))
		for _, uri := range uris {
			rendered = append(rendered, uri.String())
		}
		values = append(values, "uris", logging.List(rendered))
	}
	if addresses := logging.List(certificate.EmailAddresses); len(addresses) > 0 {
		values = append(values, "emailAddresses", addresses)
	}
	return values
}

// publicKeyDescription names the algorithm and size in bits of an issued public key.
func publicKeyDescription(key crypto.PublicKey) (string, int) {
	switch typed := key.(type) {
	case *rsa.PublicKey:
		return "RSA", typed.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", typed.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", len(typed) * 8
	default:
		return unknownKeyType, 0
	}
}

// logResumedTransaction reports that this reconcile continued a CMP transaction an earlier attempt recorded.
func logResumedTransaction(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction) {
	logger := log.FromContext(ctx)
	values := []any{"phase", transaction.Status.Phase, "polls", transaction.Status.Polls, "deadline", timestampLogValue(transaction.Spec.Deadline.Time)}
	if !transaction.CreationTimestamp.IsZero() {
		values = append(values, "age", durationLogValue(time.Since(transaction.CreationTimestamp.Time)))
	}
	// A poll cycle resumes the transaction on every reconcile and reports its own progress, so only a
	// resumption that is not already narrated by the next line is worth the default verbosity.
	if transaction.Status.Phase == cmpv1alpha1.TransactionPhasePolling || transaction.Status.Phase == cmpv1alpha1.TransactionPhaseIssued {
		logger.V(1).Info("Resumed CMP transaction", values...)
		return
	}
	logger.Info("Resumed CMP transaction", values...)
}

// logIssuedCertificate reports the outcome of a completed enrollment and how long it took.
func logIssuedCertificate(ctx context.Context, transaction *cmpv1alpha1.CMPTransaction, chain []*x509.Certificate, confirmation string, started time.Time) {
	values := append(certificateLogValues(chain), "confirmation", confirmation, "polls", transaction.Status.Polls, "duration", durationLogValue(time.Since(started)))
	log.FromContext(ctx).Info("Issued certificate", values...)
}

// logEnrollmentFailure reports a failed enrollment together with the typed CMP failure behind it.
func logEnrollmentFailure(ctx context.Context, err error) {
	var pendingErr issuersigner.PendingError
	if err == nil || errors.As(err, &pendingErr) {
		// A pending transaction is not a failure, and the wait it is retried after is already logged.
		return
	}
	logger := log.FromContext(ctx)
	var protocolError *protocol.Error
	if errors.As(err, &protocolError) {
		logger.Error(err, "CMP enrollment failed", "operation", protocolError.Operation, "failure", protocolError.Failure, "classification", string(protocolError.Kind))
		return
	}
	var configurationErr *configurationError
	if errors.As(err, &configurationErr) {
		logger.Error(err, "CMP enrollment failed", "operation", configurationErr.Operation, "failure", "issuerConfiguration", "classification", configurationClassification(configurationErr))
		return
	}
	logger.Error(err, "CMP enrollment failed")
}

// configurationClassification names the retry behavior of an issuer configuration failure.
func configurationClassification(err *configurationError) string {
	if err.Permanent {
		return string(protocol.ErrorKindPermanent)
	}
	return string(protocol.ErrorKindRetryable)
}

// enrollmentDeadlineValues describes the polling budget left for a transaction that is still open.
func enrollmentDeadlineValues(transaction *cmpv1alpha1.CMPTransaction, limits cmpv1alpha1.TransactionSpec, delay time.Duration) []any {
	return []any{"polls", transaction.Status.Polls, "maximumPolls", limits.MaximumPolls, "retryAfter", durationLogValue(delay), "deadline", timestampLogValue(transaction.Spec.Deadline.Time)}
}

// enrollmentLogValue names the CMP operation a transaction record describes.
func enrollmentLogValue(transaction *cmpv1alpha1.CMPTransaction) string {
	return fmt.Sprintf("%s v%d", transaction.Spec.Operation, transaction.Spec.ProtocolVersion)
}
