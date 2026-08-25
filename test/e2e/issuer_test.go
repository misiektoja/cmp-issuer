//go:build e2e
// +build e2e

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

package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/misiektoja/cmp-issuer/test/utils"
)

const (
	// cmpNamespace holds the issuers, credentials and requests of the issuer specs.
	cmpNamespace = "cmp-issuer-e2e"
	// controllerIdentity is the service account that the manager Deployment runs as.
	controllerIdentity = "system:serviceaccount:cmp-issuer-system:cmp-issuer-controller-manager"
	// trustSecretName holds the CMP response trust anchor of a well configured issuer.
	trustSecretName = "cmp-issuer-e2e-trust"
	// credentialSecretName holds the PasswordBasedMac reference and shared secret.
	credentialSecretName = "cmp-issuer-e2e-credentials"
	// sentinelSecretName is the Secret that a crafted private key annotation points at.
	sentinelSecretName = "cmp-issuer-e2e-sentinel"
	// sentinelValue marks the sentinel Secret so an unexpected write is visible.
	sentinelValue = "sentinel-must-not-be-consumed"
	// unreachableEndpoint refuses connections immediately so transport failures stay deterministic.
	unreachableEndpoint = "http://127.0.0.1:9/cmp"
	// recipientDN is the CMP recipient name that the specs configure.
	recipientDN = "CN=Unreachable CMP CA,O=cmp-issuer e2e"
	// readyIssuer is the fully configured issuer that the request specs submit to.
	readyIssuer = "cmp-issuer-e2e-ready"
	// unapprovedIssuer is configured the same way, but cert-manager holds no approval permission for it,
	// so the denial spec decides its requests itself instead of racing the built-in approver.
	unapprovedIssuer = "cmp-issuer-e2e-unapproved"
	// apiGroup is the API group that the issuer kinds are served in.
	apiGroup = "certmanager.misiektoja.github.io"
	// approverClusterRole is the shipped ClusterRole that grants cert-manager approval for this issuer type.
	approverClusterRole = "cmp-issuer-cert-manager-approver"
	// readinessTimeout bounds a single issuer reconciliation.
	readinessTimeout = 90 * time.Second
	// requestTimeout bounds the signing attempt of an approved CertificateRequest.
	requestTimeout = 3 * time.Minute
)

// These specs prove the controller contract that needs no CMP server. Enrollment against a real
// server is verified separately against the CMP servers recorded in the interoperability notes,
// because starting one in the cluster costs more than ten minutes per run.
var _ = Describe("CMPIssuer", Ordered, func() {
	BeforeAll(func() {
		By("creating the issuer test namespace")
		_, _ = utils.Run(exec.Command("kubectl", "create", "ns", cmpNamespace))

		By("authorizing the controller to read issuer credentials in the namespace")
		Expect(kubectlApply(cmpNamespace, credentialReaderBinding)).To(Succeed())

		By("publishing the credential and trust Secrets of a well configured issuer")
		credentials := secretManifest(credentialSecretName, map[string]string{
			"reference": "cmp-issuer-e2e",
			"secret":    "e2e-shared-secret-not-a-real-credential",
		})
		Expect(kubectlApply(cmpNamespace, credentials)).To(Succeed())
		authorityPEM, err := selfSignedAuthorityPEM()
		Expect(err).NotTo(HaveOccurred())
		trust := secretManifest(trustSecretName, map[string]string{"ca.crt": authorityPEM})
		Expect(kubectlApply(cmpNamespace, trust)).To(Succeed())
	})

	AfterAll(func() {
		By("removing the issuer test namespace")
		_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", cmpNamespace, "--ignore-not-found"))
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		By("collecting issuer resources for the failed spec")
		arguments := []string{"get", "certificate,certificaterequest,cmpissuer", "-n", cmpNamespace, "-o", "wide"}
		if output, err := utils.Run(exec.Command("kubectl", arguments...)); err == nil {
			_, _ = fmt.Fprintf(GinkgoWriter, "issuer resources:\n%s", output)
		}
	})

	It("becomes ready when its credential and trust Secrets are readable", func() {
		By("creating an issuer whose Secrets exist in its own namespace")
		manifest := passwordIssuerManifest(readyIssuer, credentialSecretName, trustSecretName, "")
		Expect(kubectlApply(cmpNamespace, manifest)).To(Succeed())

		By("waiting for the controller to accept the configuration")
		expectIssuerCondition(readyIssuer, "True", "")
	})

	It("stays unready while its credential Secret is missing", func() {
		By("creating an issuer that references a credential Secret that does not exist")
		issuer := "cmp-issuer-e2e-no-credentials"
		manifest := passwordIssuerManifest(issuer, "cmp-issuer-e2e-absent", trustSecretName, "")
		Expect(kubectlApply(cmpNamespace, manifest)).To(Succeed())

		By("waiting for the controller to report the missing Secret")
		expectIssuerCondition(issuer, "False", "cmp-issuer-e2e-absent")
	})

	It("stays unready while its trust Secret is missing", func() {
		By("creating an issuer that references a trust Secret that does not exist")
		issuer := "cmp-issuer-e2e-no-trust"
		manifest := passwordIssuerManifest(issuer, credentialSecretName, "cmp-issuer-e2e-absent-trust", "")
		Expect(kubectlApply(cmpNamespace, manifest)).To(Succeed())

		By("waiting for the controller to report the missing Secret")
		expectIssuerCondition(issuer, "False", "cmp-issuer-e2e-absent-trust")
	})

	It("accepts only the response identifiers that the API documents", func() {
		By("pinning the identifier that the standards require")
		issuer := "cmp-issuer-e2e-pinned"
		pinned := passwordIssuerManifest(issuer, credentialSecretName, trustSecretName, "-1")
		Expect(kubectlApply(cmpNamespace, pinned)).To(Succeed())

		By("rejecting an identifier outside the accepted values")
		manifest := passwordIssuerManifest("cmp-issuer-e2e-bad-pin", credentialSecretName, trustSecretName, "7")
		err := kubectlApply(cmpNamespace, manifest)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("p10crResponseCertReqId"))
	})

	It("enforces validation profile conflicts in the API", func() {
		By("creating an RFC 9483 profile with compatible focused settings")
		issuer := "cmp-issuer-e2e-rfc9483"
		manifest := passwordIssuerManifest(issuer, credentialSecretName, trustSecretName, "-1")
		manifest = strings.Replace(manifest, "    p10crResponseCertReqId: -1", "    validationProfile: RFC9483\n    kurResponseCaPubs: RequireAbsent\n    macResponseProtection: Strict\n    p10crResponseCertReqId: -1", 1)
		Expect(kubectlApply(cmpNamespace, manifest)).To(Succeed())

		By("rejecting an explicit interoperability override under RFC 9483")
		invalid := strings.Replace(manifest, "name: "+issuer, "name: cmp-issuer-e2e-rfc9483-invalid", 1)
		invalid = strings.Replace(invalid, "kurResponseCaPubs: RequireAbsent", "kurResponseCaPubs: Accept", 1)
		err := kubectlApply(cmpNamespace, invalid)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("RFC9483 requires KUP caPubs to be absent"))
	})

	It("sends no CMP message for a denied CertificateRequest", func() {
		By("creating an issuer that cert-manager holds no approval permission for")
		issuer := passwordIssuerManifest(unapprovedIssuer, credentialSecretName, trustSecretName, "")
		Expect(kubectlApply(cmpNamespace, issuer)).To(Succeed())
		expectIssuerCondition(unapprovedIssuer, "True", "")

		By("requesting a certificate that an approver will reject")
		certificate := "cmp-issuer-e2e-denied"
		manifest := fmt.Sprintf(certificateTemplate, certificate, certificate+"-tls", certificate, unapprovedIssuer)
		Expect(kubectlApply(cmpNamespace, manifest)).To(Succeed())
		request := waitForCertificateRequest(certificate)

		By("denying the CertificateRequest")
		Expect(setRequestCondition(cmpNamespace, request, "Denied", "denied by the e2e suite")).To(Succeed())

		By("confirming that the request stays denied and stores no certificate")
		Consistently(func(g Gomega) {
			conditions, err := resourceConditions("certificaterequest", cmpNamespace, request)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(findCondition(conditions, "Denied").Status).To(Equal("True"))
			g.Expect(findCondition(conditions, "Ready").Status).NotTo(Equal("True"))
			g.Expect(resourceExists("secret", cmpNamespace, certificate+"-tls")).To(BeFalse())
		}, 30*time.Second, 5*time.Second).Should(Succeed())
	})

	It("reports a transport failure without storing partial material", func() {
		By("submitting a CertificateRequest directly to an issuer whose endpoint refuses connections")
		request := "cmp-issuer-e2e-unreachable-probe"
		csrPEM, err := createCertificateRequestPEM("cmp-issuer-e2e-unreachable")
		Expect(err).NotTo(HaveOccurred())
		Expect(kubectlApply(cmpNamespace, requestManifest(request, readyIssuer, csrPEM, ""))).To(Succeed())

		By("approving the CertificateRequest")
		Expect(setRequestCondition(cmpNamespace, request, "Approved", "approved by the e2e suite")).To(Succeed())

		By("waiting for the controller to surface the transport failure")
		Eventually(func(g Gomega) {
			conditions, err := resourceConditions("certificaterequest", cmpNamespace, request)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(findCondition(conditions, "Ready").Status).To(Equal("False"))
			issued, err := issuedCertificate(cmpNamespace, request)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(issued).To(BeEmpty())
		}, requestTimeout, 5*time.Second).Should(Succeed())
	})

	It("leaves a Secret named by a crafted private key annotation untouched", func() {
		By("creating the sentinel Secret that the crafted annotation points at")
		sentinel := secretManifest(sentinelSecretName, map[string]string{"tls.key": sentinelValue})
		Expect(kubectlApply(cmpNamespace, sentinel)).To(Succeed())

		By("submitting a CertificateRequest that redirects the private key annotation")
		request := "cmp-issuer-e2e-annotation-probe"
		csrPEM, err := createCertificateRequestPEM("cmp-issuer-e2e-annotation")
		Expect(err).NotTo(HaveOccurred())
		manifest := requestManifest(request, readyIssuer, csrPEM, sentinelSecretName)
		Expect(kubectlApply(cmpNamespace, manifest)).To(Succeed())

		By("approving the CertificateRequest")
		Expect(setRequestCondition(cmpNamespace, request, "Approved", "approved by the e2e suite")).To(Succeed())

		By("waiting for the controller to finish acting on the request")
		Eventually(func(g Gomega) {
			conditions, err := resourceConditions("certificaterequest", cmpNamespace, request)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(findCondition(conditions, "Ready").Status).To(Equal("False"))
		}, requestTimeout, 5*time.Second).Should(Succeed())

		By("confirming that the sentinel Secret was neither consumed nor modified")
		entries, err := secretData(cmpNamespace, sentinelSecretName)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1))
		Expect(string(entries["tls.key"])).To(Equal(sentinelValue))
	})

	It("keeps controller Secret access inside authorized namespaces", func() {
		By("confirming that the namespace RoleBinding grants the documented access")
		allowed, err := serviceAccountCanRead(cmpNamespace, controllerIdentity, "secrets")
		Expect(err).NotTo(HaveOccurred())
		Expect(allowed).To(BeTrue())

		By("confirming that no access exists in a namespace without the RoleBinding")
		allowed, err = serviceAccountCanRead("default", controllerIdentity, "secrets")
		Expect(err).NotTo(HaveOccurred())
		Expect(allowed).To(BeFalse())
	})
})

// expectIssuerCondition waits until a CMPIssuer reports the expected Ready status and message content.
func expectIssuerCondition(issuer string, status string, message string) {
	Eventually(func(g Gomega) {
		conditions, err := resourceConditions("cmpissuer", cmpNamespace, issuer)
		g.Expect(err).NotTo(HaveOccurred())
		ready := findCondition(conditions, "Ready")
		g.Expect(ready.Status).To(Equal(status))
		if message != "" {
			g.Expect(ready.Message).To(ContainSubstring(message))
		}
	}, readinessTimeout, 5*time.Second).Should(Succeed())
}

// waitForCertificateRequest returns the CertificateRequest that cert-manager created for a Certificate.
func waitForCertificateRequest(certificate string) string {
	var request string
	Eventually(func(g Gomega) {
		found, err := certificateRequestName(cmpNamespace, certificate)
		g.Expect(err).NotTo(HaveOccurred())
		request = found
	}, time.Minute, time.Second).Should(Succeed())
	return request
}

// createCertificateRequestPEM generates the PEM certification request of a direct enrollment.
func createCertificateRequestPEM(commonName string) ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate request key: %w", err)
	}
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("create certification request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER}), nil
}

// selfSignedAuthorityPEM generates a throwaway authority certificate that stands in for CMP response trust.
func selfSignedAuthorityPEM() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("generate authority key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Unreachable CMP CA", Organization: []string{"cmp-issuer e2e"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return "", fmt.Errorf("create authority certificate: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
