# PasswordBasedMac

PasswordBasedMac (PBM) protects CMP messages with a shared reference and secret configured on the CMP server.

## Secret format

Create a Secret in the issuer credential namespace:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cmp-pbm-credentials
type: Opaque
stringData:
  reference: "<server-assigned-reference>"
  secret: "<shared-secret>"
```

Default keys are `reference` and `secret`. Override with `referenceKey` and `secretKey` in the issuer spec.

## Issuer configuration

```yaml
spec:
  protection:
    type: PasswordBasedMac
    passwordBasedMac:
      secretRef:
        name: cmp-pbm-credentials
      referenceKey: reference
      secretKey: secret
      algorithm:
        owf: SHA256
        mac: HMACSHA256
        iterationCount: 1024
```

## Algorithm fields

| Field | Allowed values | Default |
| --- | --- | --- |
| `owf` | `SHA256` | `SHA256` |
| `mac` | `HMACSHA256` | `HMACSHA256` |
| `iterationCount` | 100-1048575 | 1024 |

These must match the server's PBM profile. cmp-issuer does not negotiate weaker algorithms.

## Server setup

The reference and secret must be provisioned on the CMP server before enrollment. cmp-issuer does not register credentials over CMP.

EJBCA client mode treats the enrollment code as a one-time credential. After issuance the end entity moves to `GENERATED` and refuses further requests until an administrator resets it. See [Tested PKIs](../interoperability/tested-pkis.md).

## Rotation

Credentials are reloaded from the Secret on every reconcile. Rotating a Secret during an open transaction invalidates in-flight protection and the transaction fails within `maximumDuration`. Secret resourceVersions are not recorded. See [Known limitations](../known-limitations.md).

## Related pages

* [Message protection](message-protection.md)
* [Enrollment](enrollment.md)
