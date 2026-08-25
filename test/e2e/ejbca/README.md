# CMP server test image

The end-to-end suite can enroll from a real CMP server rather than only proving the parts of the
controller contract that need no server. The server is [EJBCA Community
Edition](https://www.ejbca.org/), running inside the same Kind cluster as the manager.

Starting a stock EJBCA image is not enough for that. It generates its certification authority, its
administrator identity and its TLS keystore on first start, and every CMP alias then has to be created
over its command line interface. This directory builds an image with all of that already applied, so a
test run only has to start a container.

## Running the tests

```sh
make test-e2e-ejbca
```

The target creates the Kind cluster, makes the server image available, builds and deploys the manager,
deploys the server and runs the enrollment specs. The image is pulled when it has been published and
built locally otherwise, so the target works on a checkout that has never seen the published image.

The remaining end-to-end specs are unaffected and keep running without a CMP server:

```sh
make test-e2e
```

## Building the image by hand

```sh
make ejbca-test-image
```

`build-image.sh` starts the upstream image, waits for it to finish deploying, runs `configure.sh`
inside it, copies the resulting state and credentials out, stops the container so the database is
written out, and bakes everything into a new image. It takes a few minutes. The settings come from the
`Makefile`, which is the single place that names the upstream release, the image reference and the
hostname.

## What the image contains

| Item | Value |
| --- | --- |
| Issuing authority | `CmpIssuerTestCA`, which signs both the issued certificates and the CMP responses |
| Administration authority | `ManagementCA`, which signs the TLS server certificate and the registration certificate |
| CMP alias `cmpissuerpbm` | RA mode, requests protected with a shared secret, responses signed by the issuing authority |
| CMP alias `cmpissuersig` | RA mode, requests protected with a certificate signature |
| CMP alias `cmpissuerkurinit` | Client mode, initial P10CR protected with a shared secret and response protected with a signature |
| CMP alias `cmpissuerkur` | Client mode, KUR protected by the certificate being updated with automatic key update enabled and KUP `caPubs` enabled |
| CMP alias `cmpissuerkurstrict` | Client mode, KUR protected by the certificate being updated with automatic key update enabled and KUP `caPubs` disabled |
| `/opt/keyfactor/cmp-issuer-e2e` | trust anchors, registration credential, alias names and the shared secret, which the specs read from the running container |

The ordinary aliases and default KUR pair keep EJBCA's `responseprotection` `signature`, so the issuing
authority signs every response including the answer to a request protected with a shared secret. The
default KUR response includes the issuing CA in `caPubs`. A passing run proves the interoperable
defaults accept both behaviors without treating a delivered certificate as a trust anchor.

After initial enrollment the second KUR flow enables `validationProfile: RFC9483` before using the
strict KUR alias, which omits `caPubs`. EJBCA returns P10CR `certReqId` `0`, so enabling the profile
before initial enrollment would correctly reject that nonconforming response.

Two authorities rather than one is deliberate. The authority that signs CMP responses is not the
authority that signed the endpoint TLS certificate, so a run proves that the two trust decisions stay
separate instead of passing because one anchor happens to cover both.

The ordinary P10CR aliases are configured in RA mode. EJBCA registers the end entity from each request,
so the same subject can enroll as often as a run needs. Two fixed client-mode end entities exercise
true KUR. Their initial P10CR goes through the HMAC alias and their next cert-manager revision goes
through the certificate-authenticated key-update alias without an administrative reset. One rotates
its key while the other reuses it.

The shared secret and the registration key travel inside a published image and protect nothing but a
throwaway authority whose signing key was generated in that same image. They are fixtures, not
credentials.

## Hostname and HTTPS

The upstream start script issues the TLS server certificate for `HTTPSERVER_HOSTNAME` and names it in
the subject alternative name. The build bakes in the Kubernetes Service name that the suite reaches the
server through, so the HTTPS specs verify the certificate rather than skip verification. `EJBCA_HOSTNAME`
in the `Makefile` and the Service in `test/e2e/ejbca_test.go` therefore have to agree, and the suite
compares them before it enrolls so a mismatch is reported as such.

## Publishing

`.github/workflows/ejbca-test-image.yml` publishes the image to the registry. It builds each
architecture on a machine of that architecture, because the configuration step runs the server itself.
It rebuilds only when the upstream release the image is built from has been republished under a new
digest, which it recognises from a second tag naming that digest. A run that finds the published image
current does nothing.

To move to a new upstream release, advance `EJBCA_VERSION` in the `Makefile`. To republish after
changing the configuration in this directory, advance `EJBCA_IMAGE_REVISION`.
