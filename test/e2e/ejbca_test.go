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
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/misiektoja/cmp-issuer/test/utils"
)

const (
	// ejbcaNamespace holds the CMP server, its credentials and the issuers that enroll from it.
	ejbcaNamespace = "cmp-issuer-e2e-ejbca"
	// ejbcaWorkload names the CMP server Deployment and the Service that publishes it.
	ejbcaWorkload = "ejbca"
	// ejbcaHTTPPort serves CMP without transport security.
	ejbcaHTTPPort = 8080
	// ejbcaHTTPSPort serves the same CMP aliases over TLS.
	ejbcaHTTPSPort = 8443
	// ejbcaStateDir is where the test image keeps the configuration it was built with.
	ejbcaStateDir = "/opt/keyfactor/cmp-issuer-e2e"
	// defaultEjbcaTestImage is the published CMP server image. The Makefile passes the same reference
	// through EJBCA_TEST_IMAGE, so the two have to be advanced together.
	defaultEjbcaTestImage = "ghcr.io/misiektoja/cmp-issuer-ejbca-test:9.3.7-2"
	// ejbcaCredentialSecret carries the PasswordBasedMac reference and shared secret.
	ejbcaCredentialSecret = "cmp-issuer-e2e-ejbca-credentials"
	// ejbcaSignatureSecret carries the registration certificate and its private key.
	ejbcaSignatureSecret = "cmp-issuer-e2e-ejbca-signature-credentials"
	// ejbcaTrustSecret carries the authority that signs CMP responses.
	ejbcaTrustSecret = "cmp-issuer-e2e-ejbca-trust"
	// ejbcaTLSTrustSecret carries the authority that signed the endpoint TLS certificate, which is a
	// different authority from the one that signs CMP responses.
	ejbcaTLSTrustSecret = "cmp-issuer-e2e-ejbca-tls-trust"
	// ejbcaPasswordHTTPIssuer enrolls with a shared secret over plain HTTP.
	ejbcaPasswordHTTPIssuer = "cmp-issuer-e2e-ejbca-password-http"
	// ejbcaPasswordHTTPSIssuer enrolls with a shared secret over TLS.
	ejbcaPasswordHTTPSIssuer = "cmp-issuer-e2e-ejbca-password-https"
	// ejbcaSignatureHTTPIssuer enrolls with a certificate signature over plain HTTP.
	ejbcaSignatureHTTPIssuer = "cmp-issuer-e2e-ejbca-signature-http"
	// ejbcaKURAlwaysIssuer updates a client-mode certificate while rotating its private key.
	ejbcaKURAlwaysIssuer = "cmp-issuer-e2e-ejbca-kur-always"
	// ejbcaKURNeverIssuer updates a client-mode certificate while retaining its private key.
	ejbcaKURNeverIssuer = "cmp-issuer-e2e-ejbca-kur-never"
	// ejbcaReadyTimeout bounds the start of the CMP server, which deploys an application server.
	ejbcaReadyTimeout = 10 * time.Minute
	// ejbcaEnrollmentTimeout bounds one enrollment through cert-manager.
	ejbcaEnrollmentTimeout = 3 * time.Minute
)

// ejbcaHostname is the name the suite reaches the CMP server through. The test image issues its TLS
// server certificate for exactly this name, so the Service, the namespace and the image have to agree
// on it. A mismatch is reported by the spec rather than left to fail as a certificate error.
var ejbcaHostname = fmt.Sprintf("%s.%s.svc.cluster.local", ejbcaWorkload, ejbcaNamespace)

// ejbcaIssuers are the issuers that cert-manager is allowed to approve requests for.
var ejbcaIssuers = []string{ejbcaPasswordHTTPIssuer, ejbcaPasswordHTTPSIssuer, ejbcaSignatureHTTPIssuer, ejbcaKURAlwaysIssuer, ejbcaKURNeverIssuer}

// ejbcaConfiguration is the configuration that the CMP server image was built with.
type ejbcaConfiguration struct {
	hostname          string
	recipient         string
	passwordAlias     string
	signatureAlias    string
	kurInitialAlias   string
	kurAlias          string
	kurAlwaysIdentity string
	kurNeverIdentity  string
	pbmReference      string
	pbmSecret         string
	responseTrust     string
	transportTrust    string
	signerCertificate string
	signerKey         string
}

// These specs enroll through a real CMP server. Everything the server needs is already configured in
// its image, so the cost of a run is the container start rather than a certification authority
// generation followed by a series of administrative commands.
var _ = Describe("EJBCA enrollment", Label("ejbca"), Ordered, func() {
	var configuration ejbcaConfiguration

	BeforeAll(func() {
		By("loading the CMP server image into the cluster")
		Expect(utils.LoadImageToKindClusterWithName(ejbcaTestImage())).To(Succeed(),
			"Failed to load the CMP server image. Run make ejbca-test-image to build it.")

		By("creating the CMP server namespace")
		_, _ = utils.Run(exec.Command("kubectl", "create", "ns", ejbcaNamespace))

		By("authorizing the controller to read issuer credentials in the namespace")
		Expect(kubectlApply(ejbcaNamespace, credentialReaderBinding)).To(Succeed())

		By("deploying the CMP server")
		workload := ejbcaWorkloadManifest(ejbcaWorkload, ejbcaTestImage(), ejbcaHTTPPort, ejbcaHTTPSPort)
		Expect(kubectlApply(ejbcaNamespace, workload)).To(Succeed())
		waitForEjbca()

		By("reading the configuration that the server image was built with")
		configuration = readEjbcaConfiguration()
		Expect(configuration.hostname).To(Equal(ejbcaHostname),
			"The server image was built for another hostname, so its TLS certificate cannot match this Service")

		By("publishing the credentials and the trust anchors of the CMP server")
		credentials := secretManifest(ejbcaCredentialSecret, map[string]string{
			"reference": configuration.pbmReference,
			"secret":    configuration.pbmSecret,
		})
		Expect(kubectlApply(ejbcaNamespace, credentials)).To(Succeed())
		signer := secretManifest(ejbcaSignatureSecret, map[string]string{
			"tls.crt": configuration.signerCertificate,
			"tls.key": configuration.signerKey,
		})
		Expect(kubectlApply(ejbcaNamespace, signer)).To(Succeed())
		responseTrust := secretManifest(ejbcaTrustSecret, map[string]string{"ca.crt": configuration.responseTrust})
		Expect(kubectlApply(ejbcaNamespace, responseTrust)).To(Succeed())
		transportTrust := secretManifest(ejbcaTLSTrustSecret, map[string]string{"ca.crt": configuration.transportTrust})
		Expect(kubectlApply(ejbcaNamespace, transportTrust)).To(Succeed())

		By("creating the issuers")
		password := fmt.Sprintf(passwordBasedMacProtection, ejbcaCredentialSecret)
		signature := fmt.Sprintf(signatureProtection, ejbcaSignatureSecret)
		transport := fmt.Sprintf(tlsTransport, ejbcaTLSTrustSecret)
		for _, issuer := range []ejbcaIssuer{
			{
				name: ejbcaPasswordHTTPIssuer, url: configuration.endpointURL("http", configuration.passwordAlias),
				recipient: configuration.recipient, protection: password, trustSecret: ejbcaTrustSecret,
			},
			{
				name: ejbcaPasswordHTTPSIssuer, url: configuration.endpointURL("https", configuration.passwordAlias),
				recipient: configuration.recipient, protection: password, trustSecret: ejbcaTrustSecret,
				transport: transport,
			},
			{
				name: ejbcaSignatureHTTPIssuer, url: configuration.endpointURL("http", configuration.signatureAlias),
				recipient: configuration.recipient, protection: signature, trustSecret: ejbcaTrustSecret,
			},
			{
				name: ejbcaKURAlwaysIssuer, url: configuration.endpointURL("http", configuration.kurInitialAlias),
				recipient: configuration.recipient, protection: password, trustSecret: ejbcaTrustSecret, renewal: "KUR", renewalURL: configuration.endpointURL("http", configuration.kurAlias),
			},
			{
				name: ejbcaKURNeverIssuer, url: configuration.endpointURL("http", configuration.kurInitialAlias),
				recipient: configuration.recipient, protection: password, trustSecret: ejbcaTrustSecret, renewal: "KUR", renewalURL: configuration.endpointURL("http", configuration.kurAlias),
			},
		} {
			Expect(kubectlApply(ejbcaNamespace, issuer.manifest())).To(Succeed())
		}
	})

	AfterAll(func() {
		By("removing the CMP server namespace")
		_, _ = utils.Run(exec.Command("kubectl", "delete", "ns", ejbcaNamespace, "--ignore-not-found"))
	})

	AfterEach(func() {
		if !CurrentSpecReport().Failed() {
			return
		}
		// The response alone does not say what the server decided, so the server log is collected for
		// every failure rather than reconstructed afterwards from a cluster that no longer exists.
		By("collecting the CMP server log for the failed spec")
		arguments := []string{"logs", "deployment/" + ejbcaWorkload, "-n", ejbcaNamespace, "--tail=200"}
		if output, err := utils.Run(exec.Command("kubectl", arguments...)); err == nil {
			_, _ = fmt.Fprintf(GinkgoWriter, "CMP server log:\n%s", output)
		}
		arguments = []string{"get", "certificate,certificaterequest,cmpissuer,cmptransaction", "-n", ejbcaNamespace, "-o", "wide"}
		if output, err := utils.Run(exec.Command("kubectl", arguments...)); err == nil {
			_, _ = fmt.Fprintf(GinkgoWriter, "enrollment resources:\n%s", output)
		}
	})

	It("becomes ready once the CMP server configuration is readable", func() {
		for _, issuer := range ejbcaIssuers {
			By("waiting for " + issuer + " to accept its configuration")
			expectNamespacedIssuerCondition(ejbcaNamespace, issuer, "True", "")
		}
	})

	It("issues a certificate protected with a shared secret over HTTP", func() {
		certificate := enrollThrough(ejbcaPasswordHTTPIssuer, "cmp-issuer-e2e-password-http")
		expectIssuedBy(certificate, configuration.responseTrust)
	})

	It("issues a certificate protected with a shared secret over HTTPS", func() {
		// An issuer that quietly enrolled over plain HTTP would pass every other assertion in this
		// spec, so the transport it actually used is checked rather than assumed. The endpoint
		// certificate is verified against an authority that did not sign the CMP responses, so
		// reaching issuance also proves the two trust decisions are made separately.
		By("confirming that the issuer really reaches the endpoint over TLS")
		Expect(issuerEndpoint(ejbcaPasswordHTTPSIssuer)).To(HavePrefix("https://"))

		certificate := enrollThrough(ejbcaPasswordHTTPSIssuer, "cmp-issuer-e2e-password-https")
		expectIssuedBy(certificate, configuration.responseTrust)
	})

	It("issues a certificate protected with a certificate signature over HTTP", func() {
		certificate := enrollThrough(ejbcaSignatureHTTPIssuer, "cmp-issuer-e2e-signature-http")
		expectIssuedBy(certificate, configuration.responseTrust)
	})

	It("updates a client-mode certificate with KUR and a new private key", func() {
		renewThroughKUR(configuration, ejbcaKURAlwaysIssuer, configuration.kurAlwaysIdentity, "Always", true)
	})

	It("updates a client-mode certificate with KUR and the existing private key", func() {
		renewThroughKUR(configuration, ejbcaKURNeverIssuer, configuration.kurNeverIdentity, "Never", false)
	})

	It("records a completed transaction for every enrollment", func() {
		By("listing the transactions that the enrollments left behind")
		arguments := []string{"get", "cmptransaction", "-n", ejbcaNamespace, "-o", "jsonpath={.items[*].status.phase}"}
		output, err := utils.Run(exec.Command("kubectl", arguments...))
		Expect(err).NotTo(HaveOccurred())
		phases := strings.Fields(output)
		Expect(phases).To(HaveLen(len(ejbcaIssuers)+2), "expected one transaction per initial enrollment and KUR")
		for _, phase := range phases {
			Expect(phase).To(Equal("Issued"))
		}
		arguments = []string{"get", "cmptransaction", "-n", ejbcaNamespace, "-o", "jsonpath={.items[*].spec.operation}"}
		output, err = utils.Run(exec.Command("kubectl", arguments...))
		Expect(err).NotTo(HaveOccurred())
		operations := strings.Fields(output)
		Expect(operations).To(HaveLen(len(ejbcaIssuers) + 2))
		Expect(operations).To(ConsistOf("P10CR", "P10CR", "P10CR", "P10CR", "P10CR", "KUR", "KUR"))
	})
})

// endpointURL returns the CMP endpoint of one alias over the requested scheme.
func (configuration ejbcaConfiguration) endpointURL(scheme string, alias string) string {
	port := ejbcaHTTPPort
	if scheme == "https" {
		port = ejbcaHTTPSPort
	}
	return fmt.Sprintf("%s://%s:%d/ejbca/publicweb/cmp/%s", scheme, ejbcaHostname, port, alias)
}

// ejbcaTestImage returns the CMP server image, which EJBCA_TEST_IMAGE overrides.
func ejbcaTestImage() string {
	if image := os.Getenv("EJBCA_TEST_IMAGE"); image != "" {
		return image
	}
	return defaultEjbcaTestImage
}

// waitForEjbca blocks until the CMP server reports itself available.
func waitForEjbca() {
	By("waiting for the CMP server to finish starting")
	arguments := []string{
		"rollout", "status", "deployment/" + ejbcaWorkload, "-n", ejbcaNamespace,
		"--timeout", ejbcaReadyTimeout.String(),
	}
	_, err := utils.Run(exec.Command("kubectl", arguments...))
	Expect(err).NotTo(HaveOccurred(), "The CMP server did not become ready")
}

// readEjbcaConfiguration copies the configuration out of the running CMP server.
//
// The values are read from the server rather than repeated here, so that a change to the server image
// reaches the specs with the image instead of having to be mirrored in this file.
func readEjbcaConfiguration() ejbcaConfiguration {
	directory := GinkgoT().TempDir()
	responseTrust := readEjbcaFile(directory, "cmp-ca.pem")
	configuration := ejbcaConfiguration{
		hostname:          readEjbcaFile(directory, "hostname"),
		passwordAlias:     readEjbcaFile(directory, "pbm-alias"),
		signatureAlias:    readEjbcaFile(directory, "signature-alias"),
		kurInitialAlias:   readEjbcaFile(directory, "kur-initial-alias"),
		kurAlias:          readEjbcaFile(directory, "kur-alias"),
		kurAlwaysIdentity: readEjbcaFile(directory, "kur-always-identity"),
		kurNeverIdentity:  readEjbcaFile(directory, "kur-never-identity"),
		pbmReference:      readEjbcaFile(directory, "pbm-reference"),
		pbmSecret:         readEjbcaFile(directory, "pbm-secret"),
		responseTrust:     responseTrust,
		transportTrust:    readEjbcaFile(directory, "management-ca.pem"),
		signerCertificate: readEjbcaFile(directory, "ra-cert.pem"),
		signerKey:         readEjbcaFile(directory, "ra-key.pem"),
	}
	// The CMP recipient is the subject of the authority that signs the responses, so it is taken from
	// that certificate instead of being written down a second time.
	authority, err := parseCertificate([]byte(responseTrust))
	Expect(err).NotTo(HaveOccurred(), "Failed to parse the CMP response trust anchor")
	configuration.recipient = authority.Subject.String()
	return configuration
}

// readEjbcaFile copies one configuration file out of the CMP server and returns its content.
func readEjbcaFile(directory string, name string) string {
	local := filepath.Join(directory, name)
	source := fmt.Sprintf("%s/%s:%s/%s", ejbcaNamespace, ejbcaPodName(), ejbcaStateDir, name)
	// The file is copied rather than printed, because a copy returns the bytes the server holds while
	// anything read from a terminal stream can carry a client message alongside them.
	_, err := utils.Run(exec.Command("kubectl", "cp", source, local))
	Expect(err).NotTo(HaveOccurred(), "Failed to read %q from the CMP server", name)
	content, err := os.ReadFile(local)
	Expect(err).NotTo(HaveOccurred(), "Failed to read the copy of %q", name)
	return string(content)
}

// issuerEndpoint returns the endpoint URL that an issuer is configured with.
func issuerEndpoint(issuer string) string {
	arguments := []string{
		"get", "cmpissuer", issuer, "-n", ejbcaNamespace, "-o", "jsonpath={.spec.endpoint.url}",
	}
	output, err := utils.Run(exec.Command("kubectl", arguments...))
	Expect(err).NotTo(HaveOccurred(), "Failed to read the endpoint of %q", issuer)
	return strings.TrimSpace(output)
}

// ejbcaPodName returns the pod that currently runs the CMP server.
func ejbcaPodName() string {
	arguments := []string{
		"get", "pods", "-n", ejbcaNamespace, "-l", "app=" + ejbcaWorkload,
		"-o", "jsonpath={.items[0].metadata.name}",
	}
	output, err := utils.Run(exec.Command("kubectl", arguments...))
	Expect(err).NotTo(HaveOccurred(), "Failed to find the CMP server pod")
	Expect(output).NotTo(BeEmpty(), "The CMP server pod is not present")
	return strings.TrimSpace(output)
}

// enrollThrough requests a certificate from an issuer and returns its name once cert-manager reports it ready.
func enrollThrough(issuer string, certificate string) string {
	By("requesting a certificate from " + issuer)
	manifest := fmt.Sprintf(certificateTemplate, certificate, certificate+"-tls", certificate, issuer)
	Expect(kubectlApply(ejbcaNamespace, manifest)).To(Succeed())

	By("waiting for cert-manager to report the certificate ready")
	Eventually(func(g Gomega) {
		conditions, err := resourceConditions("certificate", ejbcaNamespace, certificate)
		g.Expect(err).NotTo(HaveOccurred())
		ready := findCondition(conditions, "Ready")
		g.Expect(ready.Status).To(Equal("True"), "certificate not ready: %s", ready.Message)
	}, ejbcaEnrollmentTimeout, 5*time.Second).Should(Succeed())
	return certificate
}

// renewThroughKUR proves two cert-manager revisions use the selected workload-key rotation behavior.
func renewThroughKUR(configuration ejbcaConfiguration, issuer string, certificate string, rotationPolicy string, expectKeyChange bool) {
	By("requesting the initial P10CR certificate from the client-mode alias")
	Expect(kubectlApply(ejbcaNamespace, ejbcaKURCertificateManifest(certificate, rotationPolicy, issuer))).To(Succeed())
	Eventually(func(g Gomega) {
		conditions, err := resourceConditions("certificate", ejbcaNamespace, certificate)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(findCondition(conditions, "Ready").Status).To(Equal("True"))
	}, ejbcaEnrollmentTimeout, 5*time.Second).Should(Succeed())
	initialSecret, err := secretData(ejbcaNamespace, certificate+"-tls")
	Expect(err).NotTo(HaveOccurred())
	initialCertificate, err := parseCertificate(initialSecret["tls.crt"])
	Expect(err).NotTo(HaveOccurred())

	By("changing a non-identity Certificate field to trigger revision two")
	_, err = utils.Run(exec.Command("kubectl", "patch", "certificate", certificate, "-n", ejbcaNamespace, "--type=merge", "-p", `{"spec":{"duration":"2161h"}}`))
	Expect(err).NotTo(HaveOccurred())
	Eventually(func(g Gomega) {
		arguments := []string{"get", "certificate", certificate, "-n", ejbcaNamespace, "-o", "jsonpath={.status.revision}"}
		revision, err := utils.Run(exec.Command("kubectl", arguments...))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(revision)).To(Equal("2"))
		conditions, err := resourceConditions("certificate", ejbcaNamespace, certificate)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(findCondition(conditions, "Ready").Status).To(Equal("True"))
	}, ejbcaEnrollmentTimeout, 5*time.Second).Should(Succeed())
	renewedSecret, err := secretData(ejbcaNamespace, certificate+"-tls")
	Expect(err).NotTo(HaveOccurred())
	renewedCertificate, err := parseCertificate(renewedSecret["tls.crt"])
	Expect(err).NotTo(HaveOccurred())
	Expect(renewedCertificate.SerialNumber).NotTo(Equal(initialCertificate.SerialNumber))
	Expect(bytes.Equal(renewedSecret["tls.key"], initialSecret["tls.key"])).To(Equal(!expectKeyChange))
	expectIssuedBy(certificate, configuration.responseTrust)
}

// expectIssuedBy checks that the stored certificate certifies the requested name and was signed by the anchor.
func expectIssuedBy(certificate string, authorityPEM string) {
	By("reading the issued certificate out of its Secret")
	entries, err := secretData(ejbcaNamespace, certificate+"-tls")
	Expect(err).NotTo(HaveOccurred())
	Expect(entries).To(HaveKey("tls.crt"))
	Expect(entries).To(HaveKey("tls.key"))

	issued, err := parseCertificate(entries["tls.crt"])
	Expect(err).NotTo(HaveOccurred())
	Expect(issued.Subject.CommonName).To(Equal(certificate))

	By("confirming that the configured trust anchor signed it")
	// The stored chain stops below the trust anchor, because a root the operator already configured is
	// not taken from the server. The signature is therefore checked against the anchor the issuer was
	// given rather than against a certificate the Secret carries.
	authority, err := parseCertificate([]byte(authorityPEM))
	Expect(err).NotTo(HaveOccurred())
	Expect(issued.Issuer.String()).To(Equal(authority.Subject.String()))
	Expect(issued.CheckSignatureFrom(authority)).To(Succeed())
}

// parseCertificate decodes the first certificate of a PEM bundle.
func parseCertificate(bundle []byte) (*x509.Certificate, error) {
	for block, rest := pem.Decode(bundle); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, fmt.Errorf("no certificate in the %d bytes provided", len(bundle))
}

// expectNamespacedIssuerCondition waits until a CMPIssuer in the given namespace reports the expected Ready status.
func expectNamespacedIssuerCondition(namespace string, issuer string, status string, message string) {
	Eventually(func(g Gomega) {
		conditions, err := resourceConditions("cmpissuer", namespace, issuer)
		g.Expect(err).NotTo(HaveOccurred())
		ready := findCondition(conditions, "Ready")
		g.Expect(ready.Status).To(Equal(status))
		if message != "" {
			g.Expect(ready.Message).To(ContainSubstring(message))
		}
	}, readinessTimeout, 5*time.Second).Should(Succeed())
}
