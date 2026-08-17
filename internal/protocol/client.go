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
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/tsaarni/go-pkicmp/pkicmp"
)

// Bounds for inline polling of a delayed pkiConf. The certificate is already issued once certConf is
// sent, so a server that delays the confirmation is expected to answer within seconds. These bounds
// keep that wait from stalling a reconcile when a server requests an unreasonable delay.
const (
	confirmationPollMinimum = time.Second
	confirmationPollMaximum = 10 * time.Second
	confirmationPollBudget  = time.Minute
)

// CMPClient executes synchronous CMPv2 P10CR transactions with explicit transport policy.
type CMPClient struct{}

// NewClient constructs the default project-owned CMP client.
func NewClient() Client { return &CMPClient{} }

// EnrollP10CR validates inputs and executes one synchronous P10CR exchange.
func (c *CMPClient) EnrollP10CR(ctx context.Context, request EnrollmentRequest) (EnrollmentResult, error) {
	if err := validateEnrollmentRequest(request); err != nil {
		return EnrollmentResult{}, err
	}
	csr, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil {
		return EnrollmentResult{}, permanent("parse CSR", "badRequest", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return EnrollmentResult{}, permanent("verify CSR signature", "badPOP", err)
	}
	credentials, err := credentialsFor(request.Protection)
	if err != nil {
		return EnrollmentResult{}, permanent("configure protection", "badAlg", err)
	}
	sender := pkicmp.GeneralName{}
	if request.Sender != nil {
		sender = pkicmp.NewDirectoryName(*request.Sender)
	} else if request.Protection.Signature != nil {
		sender = pkicmp.NewDirectoryName(request.Protection.Signature.Certificate.Subject)
	}
	message := pkicmp.NewPKIMessage(pkicmp.NewP10CRBody(csr), pkicmp.MessageOptions{Sender: sender, Recipient: pkicmp.NewDirectoryName(request.Recipient), TransactionID: request.TransactionID})
	if request.Protection.Password != nil {
		message.Header.SenderKID = append([]byte(nil), request.Protection.Password.Reference...)
	}
	if request.ImplicitConfirm {
		message.Header.GeneralInfo = append(message.Header.GeneralInfo, pkicmp.ImplicitConfirmInfoValue())
	}
	if err := credentials.Protect(message); err != nil {
		return EnrollmentResult{}, permanent("protect P10CR", "badAlg", err)
	}
	requestDER, err := message.MarshalBinary()
	if err != nil {
		return EnrollmentResult{}, permanent("encode P10CR", "badDataFormat", err)
	}
	httpClient := newHTTPClient(request)
	responseDER, err := sendCMP(ctx, httpClient, request.EndpointURL, requestDER, request.MaxResponseSize)
	if err != nil {
		return EnrollmentResult{}, err
	}
	response, err := pkicmp.ParsePKIMessage(responseDER)
	if err != nil {
		return EnrollmentResult{}, security("parse CP", "badDataFormat", err)
	}
	responseSigner, err := verifyResponse(message, response, request, nil, nil)
	if err != nil {
		return EnrollmentResult{}, err
	}
	return finishTransaction(ctx, httpClient, request, credentials, message, response, csr, responseSigner, message.Header.SenderNonce)
}

// PollP10CR sends one pollReq for a transaction the server answered with waiting and returns either
// the issued chain or the state needed for the next poll.
func (c *CMPClient) PollP10CR(ctx context.Context, poll PollRequest) (EnrollmentResult, error) {
	request := poll.Enrollment
	if err := validateEnrollmentRequest(request); err != nil {
		return EnrollmentResult{}, err
	}
	if len(request.TransactionID) == 0 || len(poll.RecipNonce) == 0 {
		return EnrollmentResult{}, permanent("validate poll request", "badRequest", fmt.Errorf("transaction ID and recipient nonce are required to poll"))
	}
	csr, err := x509.ParseCertificateRequest(request.CSRDER)
	if err != nil {
		return EnrollmentResult{}, permanent("parse CSR", "badRequest", err)
	}
	credentials, err := credentialsFor(request.Protection)
	if err != nil {
		return EnrollmentResult{}, permanent("configure protection", "badAlg", err)
	}
	sender := pkicmp.GeneralName{}
	if request.Sender != nil {
		sender = pkicmp.NewDirectoryName(*request.Sender)
	} else if request.Protection.Signature != nil {
		sender = pkicmp.NewDirectoryName(request.Protection.Signature.Certificate.Subject)
	}
	body := pkicmp.PollReqContent{poll.CertReqID}
	message := pkicmp.NewPKIMessage(pkicmp.NewPollReqBody(&body), pkicmp.MessageOptions{Sender: sender, Recipient: pkicmp.NewDirectoryName(request.Recipient), TransactionID: request.TransactionID, RecipNonce: poll.RecipNonce})
	if request.Protection.Password != nil {
		message.Header.SenderKID = append([]byte(nil), request.Protection.Password.Reference...)
	}
	if err := credentials.Protect(message); err != nil {
		return EnrollmentResult{}, permanent("protect pollReq", "badAlg", err)
	}
	requestDER, err := message.MarshalBinary()
	if err != nil {
		return EnrollmentResult{}, permanent("encode pollReq", "badDataFormat", err)
	}
	httpClient := newHTTPClient(request)
	responseDER, err := sendCMP(ctx, httpClient, request.EndpointURL, requestDER, request.MaxResponseSize)
	if err != nil {
		return EnrollmentResult{}, err
	}
	response, err := pkicmp.ParsePKIMessage(responseDER)
	if err != nil {
		return EnrollmentResult{}, security("parse poll response", "badDataFormat", err)
	}
	responseSigner, err := verifyResponse(message, response, request, poll.ResponseSigner, poll.RequestNonce)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if response.Body.Type == pkicmp.BodyTypePollRep {
		pending, err := extractPollRep(response, poll.CertReqID, responseSigner, poll.RequestNonce)
		if err != nil {
			return EnrollmentResult{}, err
		}
		return EnrollmentResult{Pending: pending}, nil
	}
	return finishTransaction(ctx, httpClient, request, credentials, message, response, csr, responseSigner, poll.RequestNonce)
}

// finishTransaction turns an authenticated CP into a validated chain, or reports that polling continues.
// delayedRequestNonce is the sender nonce that identifies this transaction to a server that delays responses.
func finishTransaction(ctx context.Context, httpClient *http.Client, request EnrollmentRequest, credentials pkicmp.Credentials, requestMessage *pkicmp.PKIMessage, response *pkicmp.PKIMessage, csr *x509.CertificateRequest, responseSigner *x509.Certificate, delayedRequestNonce []byte) (EnrollmentResult, error) {
	issued, err := extractCP(response, request.RejectGrantedMods, request.ResponseCertReqID)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if issued.Waiting {
		return EnrollmentResult{Pending: &PendingTransaction{CertReqID: issued.CertReqID, RecipNonce: append([]byte(nil), response.Header.SenderNonce...), ResponseSigner: responseSigner, RequestNonce: append([]byte(nil), delayedRequestNonce...)}}, nil
	}
	if !PublicKeysEqual(csr.PublicKey, issued.Certificate.PublicKey) {
		return EnrollmentResult{}, security("validate issued certificate", "publicKeyMismatch", fmt.Errorf("issued certificate public key does not match CSR"))
	}
	chain, err := validateAndOrderChain(issued.Certificate, issued.Candidates, request.CMPTrust)
	if err != nil {
		return EnrollmentResult{}, security("validate issued chain", "signerNotTrusted", err)
	}
	if request.ImplicitConfirm && issued.ImplicitGranted {
		return EnrollmentResult{Chain: chain, ExtraCertificateCount: len(issued.Candidates), ExplicitConfirmation: false, ResponseCertReqID: issued.CertReqID}, nil
	}
	if err := exchangeConfirmation(ctx, httpClient, request, credentials, requestMessage, response, issued, responseSigner); err != nil {
		return EnrollmentResult{}, err
	}
	return EnrollmentResult{Chain: chain, ExtraCertificateCount: len(issued.Candidates), ExplicitConfirmation: true, ResponseCertReqID: issued.CertReqID}, nil
}

// extractPollRep validates a pollRep body and returns the state required for the next poll.
func extractPollRep(response *pkicmp.PKIMessage, expectedCertReqID int64, responseSigner *x509.Certificate, delayedRequestNonce []byte) (*PendingTransaction, error) {
	reply, err := response.Body.PollRep()
	if err != nil {
		return nil, permanent("parse pollRep", "badDataFormat", err)
	}
	if len(*reply) != 1 {
		return nil, permanent("validate pollRep", "badRequest", fmt.Errorf("pollRep must contain exactly one entry"))
	}
	item := (*reply)[0]
	if item.CertReqID != expectedCertReqID {
		return nil, security("validate pollRep certReqId", "certReqIdMismatch", fmt.Errorf("pollRep certReqId does not match the polled request"))
	}
	if item.CheckAfter < 0 {
		return nil, permanent("validate pollRep", "badRequest", fmt.Errorf("pollRep checkAfter is negative"))
	}
	return &PendingTransaction{CertReqID: item.CertReqID, RecipNonce: append([]byte(nil), response.Header.SenderNonce...), ResponseSigner: responseSigner, CheckAfter: time.Duration(item.CheckAfter) * time.Second, RequestNonce: append([]byte(nil), delayedRequestNonce...)}, nil
}

// validateEnrollmentRequest rejects unsupported or unsafe transaction configurations.
func validateEnrollmentRequest(request EnrollmentRequest) error {
	parsedURL, err := url.Parse(request.EndpointURL)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return permanent("validate endpoint", "badRequest", fmt.Errorf("endpoint must be a complete HTTP or HTTPS URL"))
	}
	if request.Timeout <= 0 || request.MaxResponseSize <= 0 {
		return permanent("validate transport limits", "badRequest", fmt.Errorf("positive timeout and response size are required"))
	}
	if len(request.CSRDER) == 0 || request.CMPTrust == nil {
		return permanent("validate request", "badRequest", fmt.Errorf("CSR and CMP trust are required"))
	}
	if (request.Protection.Password == nil) == (request.Protection.Signature == nil) {
		return permanent("validate protection", "badRequest", fmt.Errorf("exactly one protection mode is required"))
	}
	if request.Protection.Password != nil {
		if len(request.Protection.Password.Reference) == 0 || len(request.Protection.Password.Secret) == 0 {
			return permanent("validate PasswordBasedMac", "badRequest", fmt.Errorf("reference and shared secret are required"))
		}
		if request.Protection.Password.IterationCount < 100 || request.Protection.Password.IterationCount > 1048575 {
			return permanent("validate PasswordBasedMac", "badRequest", fmt.Errorf("iteration count is outside supported bounds"))
		}
	}
	if request.Protection.Signature != nil {
		if err := ValidateSignerCertificate(request.Protection.Signature.PrivateKey, request.Protection.Signature.Certificate); err != nil {
			return permanent("validate signature credentials", "badRequest", err)
		}
	}
	return nil
}

// credentialsFor constructs reviewed go-pkicmp credentials without exposing dependency types.
func credentialsFor(protection Protection) (pkicmp.Credentials, error) {
	if protection.Password != nil {
		return pkicmp.NewMACCredentials(protection.Password.Secret, pkicmp.WithPBM(), pkicmp.WithMACIterationCount(protection.Password.IterationCount))
	}
	return pkicmp.NewSignatureCredentials(protection.Signature.PrivateKey, protection.Signature.Certificate, protection.Signature.Chain...)
}

// newHTTPClient constructs a bounded transport that disables redirects.
func newHTTPClient(request EnrollmentRequest) *http.Client {
	dialer := &net.Dialer{Timeout: request.Timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: dialer.DialContext, ForceAttemptHTTP2: false, MaxIdleConns: 16, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: request.Timeout, ResponseHeaderTimeout: request.Timeout, ExpectContinueTimeout: time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: request.TLSRoots}}
	return &http.Client{Transport: transport, Timeout: request.Timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

// sendCMP posts protected DER and accepts authenticated CMP bodies without deriving state from HTTP metadata.
func sendCMP(ctx context.Context, client *http.Client, endpoint string, requestDER []byte, maximum int64) ([]byte, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestDER))
	if err != nil {
		return nil, permanent("create HTTP request", "badRequest", err)
	}
	httpRequest.Header.Set("Content-Type", "application/pkixcmp")
	httpRequest.Header.Set("Accept", "application/pkixcmp")
	httpResponse, err := client.Do(httpRequest)
	if err != nil {
		return nil, retryable("HTTP exchange", "systemUnavail", err)
	}
	defer func() { _ = httpResponse.Body.Close() }()
	if httpResponse.StatusCode >= 300 && httpResponse.StatusCode < 400 {
		return nil, permanent("HTTP exchange", "redirectRejected", fmt.Errorf("redirect response rejected"))
	}
	mediaType, _, parseErr := mime.ParseMediaType(httpResponse.Header.Get("Content-Type"))
	if parseErr != nil || mediaType != "application/pkixcmp" {
		if httpResponse.StatusCode >= 500 {
			return nil, retryable("HTTP exchange", "systemUnavail", fmt.Errorf("server returned HTTP %d without a CMP body", httpResponse.StatusCode))
		}
		return nil, permanent("HTTP exchange", "badDataFormat", fmt.Errorf("response is not application/pkixcmp"))
	}
	body, err := io.ReadAll(io.LimitReader(httpResponse.Body, maximum+1))
	if err != nil {
		return nil, retryable("read HTTP response", "systemUnavail", err)
	}
	if int64(len(body)) > maximum {
		return nil, permanent("read HTTP response", "responseTooLarge", fmt.Errorf("CMP response exceeds configured limit"))
	}
	if len(body) == 0 {
		return nil, permanent("read HTTP response", "badDataFormat", fmt.Errorf("CMP response is empty"))
	}
	return body, nil
}

// verifyResponse authenticates the response and returns its trusted signature certificate when present.
// delayedRequestNonce is the sender nonce of an earlier request whose response the server delayed.
// RFC 9483 section 3.5 accepts it in place of the preceding request nonce during delayed delivery,
// and section 4.4 requires the client to check the final polled response against it.
func verifyResponse(requestMessage *pkicmp.PKIMessage, response *pkicmp.PKIMessage, request EnrollmentRequest, previousSigner *x509.Certificate, delayedRequestNonce []byte) (*x509.Certificate, error) {
	if response.Header.ProtectionAlg == nil || len(response.Protection) == 0 {
		return nil, security("verify response protection", "missingProtection", fmt.Errorf("response has no PKIProtection"))
	}
	sharedSecret := []byte(nil)
	if request.Protection.Password != nil {
		sharedSecret = request.Protection.Password.Secret
	}
	var responseSigner *x509.Certificate
	verification, verificationErr := response.Verify(pkicmp.VerifyOptions{SharedSecret: sharedSecret, TrustPool: request.CMPTrust, ExtraCerts: response.ExtraCerts, SenderKID: response.Header.SenderKID})
	if verificationErr == nil && !verification.MACVerified {
		responseSigner, verificationErr = verifyTrustedSignature(response, request.CMPTrust)
	}
	if verificationErr != nil && previousSigner != nil {
		if _, previousErr := response.Verify(pkicmp.VerifyOptions{TrustedCert: previousSigner}); previousErr == nil {
			responseSigner = previousSigner
			verificationErr = nil
		}
	}
	if verificationErr != nil {
		fallbackSigner, fallbackErr := verifyTrustedSignature(response, request.CMPTrust)
		if fallbackErr != nil {
			return nil, security("verify response protection", "badMessageCheck", verificationErr)
		}
		responseSigner = fallbackSigner
	}
	if !bytes.Equal(response.Header.TransactionID, requestMessage.Header.TransactionID) {
		return nil, security("verify transaction ID", "transactionIdMismatch", fmt.Errorf("response transaction ID does not match request"))
	}
	if !acceptableRecipNonce(response.Header.RecipNonce, requestMessage.Header.SenderNonce, delayedRequestNonce) {
		return nil, security("verify recipient nonce", "nonceMismatch", fmt.Errorf("response recipient nonce does not match request sender nonce"))
	}
	if response.Header.PVNO != pkicmp.PVNO2 {
		return nil, permanent("verify protocol version", "unsupportedVersion", fmt.Errorf("response protocol version is not CMPv2"))
	}
	return responseSigner, nil
}

// acceptableRecipNonce reports whether a response echoes a nonce that links it to this transaction.
// RFC 9483 section 3.5 accepts the sender nonce of the preceding request, or during delayed delivery
// the sender nonce of the request whose response the server delayed.
func acceptableRecipNonce(recipNonce []byte, requestNonce []byte, delayedRequestNonce []byte) bool {
	if bytes.Equal(recipNonce, requestNonce) {
		return true
	}
	return len(delayedRequestNonce) > 0 && bytes.Equal(recipNonce, delayedRequestNonce)
}

// verifyTrustedSignature independently verifies a signature signer chain without treating senderKID as an authorization value.
func verifyTrustedSignature(message *pkicmp.PKIMessage, roots *x509.CertPool) (*x509.Certificate, error) {
	if roots == nil {
		return nil, fmt.Errorf("CMP trust anchors are absent")
	}
	parsed := make([]*x509.Certificate, 0, len(message.ExtraCerts))
	intermediates := x509.NewCertPool()
	for _, encoded := range message.ExtraCerts {
		certificate, err := encoded.Parse()
		if err != nil {
			continue
		}
		parsed = append(parsed, certificate)
		intermediates.AddCert(certificate)
	}
	for _, certificate := range parsed {
		if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			continue
		}
		if _, err := message.Verify(pkicmp.VerifyOptions{TrustedCert: certificate}); err == nil {
			return certificate, nil
		}
	}
	return nil, fmt.Errorf("no response signer has a valid signature and chain")
}

// issuedCertificate contains the validated CP contents needed for trust validation and confirmation.
type issuedCertificate struct {
	Certificate     *x509.Certificate
	Candidates      []*x509.Certificate
	CertReqID       int64
	ImplicitGranted bool
	// Waiting reports that the server accepted the request but has not decided yet.
	Waiting bool
}

// extractCP validates the P10CR response status and returns the issued certificate with its candidates.
func extractCP(response *pkicmp.PKIMessage, rejectGrantedMods bool, pinnedCertReqID *int64) (issuedCertificate, error) {
	if response.Body.Type == pkicmp.BodyTypeError {
		content, err := response.Body.Error()
		if err != nil {
			return issuedCertificate{}, permanent("parse error response", "badDataFormat", err)
		}
		return issuedCertificate{}, classifyStatus(content.PKIStatusInfo)
	}
	if response.Body.Type != pkicmp.BodyTypeCP {
		return issuedCertificate{}, permanent("validate response body", "unsupportedBody", fmt.Errorf("expected CP response"))
	}
	reply, err := response.Body.CP()
	if err != nil {
		return issuedCertificate{}, permanent("parse CP", "badDataFormat", err)
	}
	if len(reply.Response) != 1 {
		return issuedCertificate{}, permanent("validate CP", "badRequest", fmt.Errorf("CP must contain exactly one CertResponse"))
	}
	certificateResponse := reply.Response[0]
	if err := acceptResponseCertReqID(certificateResponse.CertReqID, pinnedCertReqID); err != nil {
		return issuedCertificate{}, err
	}
	if certificateResponse.Status.Status == pkicmp.StatusWaiting {
		return issuedCertificate{CertReqID: certificateResponse.CertReqID, Waiting: true}, nil
	}
	if statusErr := classifyStatus(certificateResponse.Status); statusErr != nil {
		return issuedCertificate{}, statusErr
	}
	if certificateResponse.Status.Status == pkicmp.StatusGrantedWithMods && rejectGrantedMods {
		return issuedCertificate{}, permanent("apply granted modifications policy", "grantedWithMods", fmt.Errorf("server granted the request with modifications"))
	}
	if certificateResponse.CertifiedKeyPair == nil || certificateResponse.CertifiedKeyPair.CertOrEncCert.Certificate == nil {
		return issuedCertificate{}, permanent("extract certificate", "badDataFormat", fmt.Errorf("CP does not contain a plaintext certificate"))
	}
	certificate, err := certificateResponse.CertifiedKeyPair.CertOrEncCert.Certificate.Parse()
	if err != nil {
		return issuedCertificate{}, permanent("parse issued certificate", "badDataFormat", err)
	}
	candidates := make([]*x509.Certificate, 0, len(reply.CAPubs)+len(response.ExtraCerts))
	for _, encoded := range append(reply.CAPubs, response.ExtraCerts...) {
		parsed, err := encoded.Parse()
		if err != nil {
			return issuedCertificate{}, permanent("parse response certificate", "badDataFormat", err)
		}
		candidates = append(candidates, parsed)
	}
	return issuedCertificate{Certificate: certificate, Candidates: candidates, CertReqID: certificateResponse.CertReqID, ImplicitGranted: responseGrantsImplicitConfirm(response)}, nil
}

// acceptResponseCertReqID enforces a pinned P10CR response identifier or the two interoperable values.
func acceptResponseCertReqID(observed int64, pinned *int64) error {
	if pinned != nil {
		if observed != *pinned {
			return security("validate CP certReqId", "certReqIdMismatch", fmt.Errorf("P10CR CP certReqId must be %d but response contained %d", *pinned, observed))
		}
		return nil
	}
	if observed != ResponseCertReqIDStandard && observed != ResponseCertReqIDLegacyZero {
		return security("validate CP certReqId", "certReqIdUnsupported", fmt.Errorf("P10CR CP certReqId must be %d or %d but response contained %d", ResponseCertReqIDStandard, ResponseCertReqIDLegacyZero, observed))
	}
	return nil
}

// responseGrantsImplicitConfirm detects the reviewed implicitConfirm OID without hard-coding it.
func responseGrantsImplicitConfirm(response *pkicmp.PKIMessage) bool {
	target := pkicmp.ImplicitConfirmInfoValue().InfoType
	for _, information := range response.Header.GeneralInfo {
		if information.InfoType.Equal(target) {
			return true
		}
	}
	return false
}

// classifyStatus maps CMP status and failure bits to typed controller behavior.
func classifyStatus(status pkicmp.PKIStatusInfo) error {
	if status.Status == pkicmp.StatusAccepted || status.Status == pkicmp.StatusGrantedWithMods {
		return nil
	}
	statusErr := status.AsError()
	if status.Status == pkicmp.StatusWaiting {
		return &Error{Kind: ErrorKindPending, Operation: "wait for certificate", Failure: "waiting", RequeueAfter: time.Second, Err: statusErr}
	}
	permanentBits := pkicmp.FailBadPOP | pkicmp.FailBadRequest | pkicmp.FailBadCertTemplate | pkicmp.FailNotAuthorized | pkicmp.FailBadAlg | pkicmp.FailBadMessageCheck | pkicmp.FailSignerNotTrusted
	if status.FailInfo&permanentBits != 0 {
		return permanent("process PKIStatus", status.FailInfo.String(), statusErr)
	}
	if status.FailInfo&(pkicmp.FailSystemUnavail|pkicmp.FailSystemFailure) != 0 {
		return retryable("process PKIStatus", status.FailInfo.String(), statusErr)
	}
	return permanent("process PKIStatus", "unknownStatus", statusErr)
}

// validateAndOrderChain verifies trust and returns the leaf followed by non-root intermediates.
func validateAndOrderChain(leaf *x509.Certificate, candidates []*x509.Certificate, roots *x509.CertPool) ([]*x509.Certificate, error) {
	intermediates := x509.NewCertPool()
	for _, candidate := range candidates {
		if !bytes.Equal(candidate.Raw, leaf.Raw) {
			intermediates.AddCert(candidate)
		}
	}
	verifiedChains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, err
	}
	if len(verifiedChains) == 0 {
		return nil, fmt.Errorf("certificate verification returned no chain")
	}
	chain := []*x509.Certificate{leaf}
	for index := 1; index < len(verifiedChains[0]); index++ {
		certificate := verifiedChains[0][index]
		if bytes.Equal(certificate.RawSubject, certificate.RawIssuer) && certificate.CheckSignatureFrom(certificate) == nil {
			break
		}
		chain = append(chain, certificate)
	}
	return chain, nil
}

// exchangeConfirmation sends certConf and requires a protected linked pkiConf response, polling while
// the server reports the confirmation as delayed. RFC 9483 section 4.4 applies delayed delivery to
// every operation, so a server may answer certConf with an error carrying status waiting. Unlike a
// pending enrollment the certificate is already issued at this point, so the remaining wait is short
// and is completed inline within bounds rather than through durable transaction state.
func exchangeConfirmation(ctx context.Context, client *http.Client, request EnrollmentRequest, credentials pkicmp.Credentials, enrollmentRequest *pkicmp.PKIMessage, enrollmentResponse *pkicmp.PKIMessage, issued issuedCertificate, responseSigner *x509.Certificate) error {
	certificateHash, err := certificateHash(issued.Certificate)
	if err != nil {
		return permanent("compute certificate hash", "badAlg", err)
	}
	confirmation := pkicmp.CertConfirmContent{{CertHash: certificateHash, CertReqID: issued.CertReqID}}
	message := pkicmp.NewPKIMessage(pkicmp.NewCertConfBody(&confirmation), pkicmp.MessageOptions{Sender: enrollmentRequest.Header.Sender, Recipient: enrollmentRequest.Header.Recipient, TransactionID: enrollmentRequest.Header.TransactionID, RecipNonce: enrollmentResponse.Header.SenderNonce})
	message.Header.SenderKID = append([]byte(nil), enrollmentRequest.Header.SenderKID...)
	confirmationNonce := append([]byte(nil), message.Header.SenderNonce...)
	response, err := exchangeProtected(ctx, client, request, credentials, message, responseSigner, nil, "certConf")
	if err != nil {
		return err
	}
	deadline := time.Now().Add(confirmationPollBudget)
	for {
		if response.Body.Type == pkicmp.BodyTypePKIConf {
			return nil
		}
		checkAfter, err := confirmationDelay(response)
		if err != nil {
			return err
		}
		wait := clampConfirmationDelay(checkAfter)
		if time.Now().Add(wait).After(deadline) {
			return permanent("await pkiConf", "systemUnavail", fmt.Errorf("server did not confirm the transaction within %s", confirmationPollBudget))
		}
		select {
		case <-ctx.Done():
			return retryable("await pkiConf", "systemUnavail", ctx.Err())
		case <-time.After(wait):
		}
		// RFC 9483 section 4.4 requires certReqId -1 when polling for a delayed response that is a
		// whole message rather than a CertResponse element.
		poll := pkicmp.PollReqContent{ResponseCertReqIDStandard}
		message = pkicmp.NewPKIMessage(pkicmp.NewPollReqBody(&poll), pkicmp.MessageOptions{Sender: enrollmentRequest.Header.Sender, Recipient: enrollmentRequest.Header.Recipient, TransactionID: enrollmentRequest.Header.TransactionID, RecipNonce: response.Header.SenderNonce})
		message.Header.SenderKID = append([]byte(nil), enrollmentRequest.Header.SenderKID...)
		response, err = exchangeProtected(ctx, client, request, credentials, message, responseSigner, confirmationNonce, "pollReq")
		if err != nil {
			return err
		}
	}
}

// confirmationDelay reports the wait requested by a server that has not yet returned pkiConf, and
// fails when the response is neither a delay nor a confirmation.
func confirmationDelay(response *pkicmp.PKIMessage) (time.Duration, error) {
	switch response.Body.Type {
	case pkicmp.BodyTypeError:
		content, err := response.Body.Error()
		if err != nil {
			return 0, permanent("parse confirmation error", "badDataFormat", err)
		}
		if content.PKIStatusInfo.Status != pkicmp.StatusWaiting {
			if statusErr := classifyStatus(content.PKIStatusInfo); statusErr != nil {
				return 0, statusErr
			}
			return 0, permanent("validate confirmation", "unsupportedBody", fmt.Errorf("expected pkiConf response"))
		}
		return 0, nil
	case pkicmp.BodyTypePollRep:
		reply, err := response.Body.PollRep()
		if err != nil {
			return 0, permanent("parse confirmation pollRep", "badDataFormat", err)
		}
		if len(*reply) != 1 {
			return 0, permanent("validate confirmation pollRep", "badRequest", fmt.Errorf("pollRep must contain exactly one entry"))
		}
		item := (*reply)[0]
		if item.CertReqID != ResponseCertReqIDStandard {
			return 0, security("validate confirmation pollRep certReqId", "certReqIdMismatch", fmt.Errorf("pollRep certReqId does not match the polled confirmation"))
		}
		if item.CheckAfter < 0 {
			return 0, permanent("validate confirmation pollRep", "badRequest", fmt.Errorf("pollRep checkAfter is negative"))
		}
		return time.Duration(item.CheckAfter) * time.Second, nil
	default:
		return 0, permanent("validate confirmation", "unsupportedBody", fmt.Errorf("expected pkiConf response"))
	}
}

// clampConfirmationDelay bounds a server requested confirmation delay so one reconcile cannot stall.
func clampConfirmationDelay(checkAfter time.Duration) time.Duration {
	if checkAfter < confirmationPollMinimum {
		return confirmationPollMinimum
	}
	if checkAfter > confirmationPollMaximum {
		return confirmationPollMaximum
	}
	return checkAfter
}

// exchangeProtected protects, sends and authenticates one message of the confirmation exchange.
func exchangeProtected(ctx context.Context, client *http.Client, request EnrollmentRequest, credentials pkicmp.Credentials, message *pkicmp.PKIMessage, responseSigner *x509.Certificate, delayedRequestNonce []byte, operation string) (*pkicmp.PKIMessage, error) {
	if err := credentials.Protect(message); err != nil {
		return nil, permanent("protect "+operation, "badAlg", err)
	}
	requestDER, err := message.MarshalBinary()
	if err != nil {
		return nil, permanent("encode "+operation, "badDataFormat", err)
	}
	responseDER, err := sendCMP(ctx, client, request.EndpointURL, requestDER, request.MaxResponseSize)
	if err != nil {
		return nil, err
	}
	response, err := pkicmp.ParsePKIMessage(responseDER)
	if err != nil {
		return nil, security("parse "+operation+" response", "badDataFormat", err)
	}
	if _, err := verifyResponse(message, response, request, responseSigner, delayedRequestNonce); err != nil {
		return nil, err
	}
	return response, nil
}

// certificateHash computes the certConf digest selected by the certificate signature algorithm.
func certificateHash(certificate *x509.Certificate) ([]byte, error) {
	var hash crypto.Hash
	switch certificate.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		hash = crypto.SHA1
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		hash = crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		hash = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		hash = crypto.SHA512
	default:
		return nil, fmt.Errorf("unsupported certificate signature algorithm")
	}
	if !hash.Available() {
		return nil, fmt.Errorf("certificate hash is unavailable")
	}
	digest := hash.New()
	_, _ = digest.Write(certificate.Raw)
	return digest.Sum(nil), nil
}

// permanent constructs a non-retryable protocol error.
func permanent(operation string, failure string, err error) *Error {
	return &Error{Kind: ErrorKindPermanent, Operation: operation, Failure: failure, Err: err}
}

// retryable constructs a retryable protocol error.
func retryable(operation string, failure string, err error) *Error {
	return &Error{Kind: ErrorKindRetryable, Operation: operation, Failure: failure, Err: err}
}

// security constructs a permanent authenticated-transaction failure.
func security(operation string, failure string, err error) *Error {
	return &Error{Kind: ErrorKindSecurity, Operation: operation, Failure: failure, Err: err}
}
