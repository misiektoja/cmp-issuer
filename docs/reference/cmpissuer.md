# CMPIssuer

`CMPIssuer` is a namespaced cert-manager issuer. Credential and trust Secrets are read from the **same namespace** as the issuer.

## API

| Field | Value |
| --- | --- |
| API group | `certmanager.misiektoja.github.io` |
| Version | `v1alpha1` |
| Kind | `CMPIssuer` |
| Scope | Namespaced |
| cert-manager issuer type | `cmpissuers.certmanager.misiektoja.github.io` |

## Minimal example

```yaml
apiVersion: certmanager.misiektoja.github.io/v1alpha1
kind: CMPIssuer
metadata:
  name: example
  namespace: application
spec:
  endpoint:
    url: https://cmp.example.net/pkix/
    timeout: 30s
    maxResponseSize: 1048576
  protocol:
    version: 2
    initialEnrollment: P10CR
    recipient: CN=Example CA,O=Example
    confirmation: Explicit
  protection:
    type: PasswordBasedMac
    passwordBasedMac:
      secretRef:
        name: cmp-pbm-credentials
  cmpTrust:
    caSecretRef:
      name: cmp-trust
      key: ca.crt
```

## Spec fields

`CMPIssuer` and `CMPClusterIssuer` share `spec`. See the tables below.

### `spec.endpoint`

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `url` | yes | | Complete HTTP or HTTPS CMP URL |
| `timeout` | yes | `30s` | Per HTTP exchange timeout |
| `maxResponseSize` | yes | `1048576` | Maximum response body in bytes (1024-10485760) |

### `spec.protocol`

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `version` | yes | `2` | CMP version; only `2` is supported |
| `initialEnrollment` | yes | `P10CR` | Only `P10CR` is implemented |
| `recipient` | yes | | RFC 4514 recipient DN |
| `confirmation` | yes | `Explicit` | `Explicit` sends `certConf`; `Implicit` requests server-granted implicit confirmation |
| `p10crResponseCertReqId` | no | accept `-1` or `0` | Pin `-1` or `0` when the server behavior is known |
| `certProfile` | no | | Optional server certificate profile |
| `sender` | no | | Optional sender DN |

### `spec.protection`

Exactly one protection mode must be configured.

| `type` | Block | Description |
| --- | --- | --- |
| `PasswordBasedMac` | `passwordBasedMac` | Shared reference and secret in a Secret |
| `Signature` | `signature` | Bootstrap certificate, private key and optional chain in a Secret |

See [PasswordBasedMac](../guide/password-based-mac.md) and [Signature protection](../guide/signature-protection.md).

### `spec.cmpTrust`

| Field | Required | Description |
| --- | --- | --- |
| `caSecretRef.name` | yes | Secret containing PEM trust anchors |
| `caSecretRef.key` | yes | Key within the Secret data |

### `spec.transport`

Optional HTTPS settings. Omit for HTTP or for HTTPS validated with the system trust store.

| Field | Description |
| --- | --- |
| `tls.caSecretRef` | PEM trust anchors for the HTTPS server |
| `tls.clientCertificateSecretRef` | Reserved for future mTLS |

See [HTTP and HTTPS transport](../guide/transport.md).

### `spec.transaction`

Bounds asynchronous enrollments. Defaults: `maximumDuration: 10m`, `minimumPollInterval: 1s`, `maximumPollInterval: 5m`, `maximumPolls: 60`.

### `spec.policy`

| Field | Default | Description |
| --- | --- | --- |
| `grantedModifications` | `Reject` | `Reject` or `Accept` certificates with `grantedWithMods` |

## Status

Ready condition follows issuer-lib conventions. When credential or trust Secrets are unreadable the message names the Secret.

## RBAC

Create the RoleBinding from [Credential Secret access](../operations/secret-access.md) in the issuer namespace before expecting Ready=True.

## Related pages

* [CMPClusterIssuer](cmpclusterissuer.md) for cluster-scoped issuers
* [Enrollment](../guide/enrollment.md)
* [Tested PKIs](../interoperability/tested-pkis.md)
