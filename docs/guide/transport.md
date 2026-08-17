# HTTP and HTTPS transport

cmp-issuer sends CMP as `application/pkixcmp` over HTTP or HTTPS. Transport security is separate from CMP message protection.

## Endpoint URL

Set the complete URL in `spec.endpoint.url`:

```yaml
spec:
  endpoint:
    url: http://192.168.1.10:8080/pkix/
    timeout: 30s
    maxResponseSize: 1048576
```

Requirements:

* Scheme must be `http` or `https`
* Path must match the server's CMP servlet or gateway
* No trailing whitespace

## HTTP

HTTP is a first-class transport. CMP message protection still applies to every request and response.

An HTTP issuer can reach Ready=True. The controller emits a one-time warning that the endpoint provides no transport confidentiality. This is informational, not a hard failure.

Use HTTP only on networks where eavesdropping is acceptable or where another layer provides confidentiality.

## HTTPS

For HTTPS endpoints configure optional custom trust:

```yaml
spec:
  endpoint:
    url: https://cmp.example.net/pkix/
  transport:
    tls:
      caSecretRef:
        name: cmp-tls-trust
        key: ca.crt
```

When `transport.tls.caSecretRef` is omitted the client uses the system root CAs bundled in the controller image.

### TLS and CMP trust are independent

| Setting | Validates |
| --- | --- |
| `spec.transport.tls.caSecretRef` | HTTPS server certificate |
| `spec.cmpTrust.caSecretRef` | CMP PKIProtection signers and issued chains |

A private CA may sign CMP responses while a public CA terminates HTTPS, or both may share a hierarchy. Configure each trust store explicitly.

## Client behavior

| Behavior | Setting |
| --- | --- |
| Redirects | Disabled; 3xx responses fail permanently |
| HTTP/2 | Disabled for the CMP client |
| Minimum TLS | TLS 1.2 |
| Timeout | `spec.endpoint.timeout` per exchange |
| Maximum body | `spec.endpoint.maxResponseSize` |

CMP transaction state is derived only from authenticated CMP DER, not from HTTP headers or cookies.

## mTLS

`spec.transport.tls.clientCertificateSecretRef` is reserved for a future release. It is not used today.

## Related pages

* [Message protection](message-protection.md)
* [CMP response trust](cmp-response-trust.md)
