# Troubleshooting

Common failure modes and where to look. Never paste credential values, private keys or protected CMP DER into tickets or Events.

## Reading the controller log

The controller log is the first place to look for anything that resource conditions do not explain.

```bash
kubectl logs -n cmp-issuer-system deploy/cmp-issuer-controller-manager -c manager -f
```

Useful variations:

```bash
# Follow by label rather than by Deployment name
kubectl logs -n cmp-issuer-system -l app.kubernetes.io/name=cmp-issuer -c manager -f

# What the previous container said before it restarted
kubectl logs -n cmp-issuer-system deploy/cmp-issuer-controller-manager -c manager --previous

# Only the last few minutes
kubectl logs -n cmp-issuer-system deploy/cmp-issuer-controller-manager -c manager --since=5m

# Everything about one request
kubectl logs -n cmp-issuer-system deploy/cmp-issuer-controller-manager -c manager | grep <certificaterequest-name>
```

The container is named `manager`. Adjust the namespace and Deployment name if you installed under a
different release name or namespace.

### What the log contains

Every failed reconcile is logged with the typed failure that caused it, which is the same message that
appears on the `CertificateRequest` condition, for example:

```text
{"level":"error","logger":"Reconcile","msg":"Got an error, will be retried.",
 "CertificateRequest":{"name":"demo-tls-1","namespace":"demo"},
 "error":"CMP process PKIStatus failed: pkicmp: status rejection, failInfo: badRequest, ..."}
```

A successful enrollment is quiet. The controller emits no per-message log line of its own, so the log
tells you why something failed rather than narrating what succeeded. Use `kubectl get cmptransactions`
to follow progress and the `CertificateRequest` conditions and Events for the outcome.

**The log never contains credential values, private keys, CSR bodies or protected CMP message bytes.**
Server-supplied status text is included in failure messages, because that is usually the reason you
need. Raising verbosity is therefore safe on a running system.

### Increasing verbosity

Raising the level adds controller-runtime internals such as cache syncs, leader election and client
activity. It does **not** add CMP protocol detail, since the controller emits no message-level logging
of its own. Raise it when you suspect a controller or Kubernetes API problem rather than a CMP one:

```bash
helm upgrade cmp-issuer cmp-issuer/cmp-issuer \
  --namespace cmp-issuer-system \
  --reuse-values \
  --set logging.level=debug
```

| Value | Purpose |
| --- | --- |
| `logging.level` | `debug`, `info`, `error`, or an integer where higher is more verbose. Default `info` |
| `logging.stacktraceLevel` | Level at and above which a stack trace is attached, `info`, `error` or `panic`. Default `panic` |
| `logging.encoder` | `json` for log collectors, `console` for reading by eye. Default `json` |

Set `logging.encoder=console` while debugging by hand, since JSON is hard to scan in a terminal.

With the manifest installation, pass the same settings as container arguments instead:
`--zap-log-level=debug`, `--zap-stacktrace-level=error` and `--zap-encoder=console`.

Return the level to `info` afterwards, since debug is noisy on a busy cluster.

## Issuer not Ready

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Ready=False, message names a Secret | Credential or trust Secret missing or unreadable | Create the Secret; for `CMPIssuer` add the RoleBinding from [Credential Secret access](secret-access.md) |
| Ready=False after install | Controller not running | `kubectl -n cmp-issuer-system get pods` |

## CertificateRequest stuck or failed

```bash
kubectl describe certificaterequest <name> -n <namespace>
kubectl get cmptransactions -n <namespace>
kubectl logs -n cmp-issuer-system deploy/cmp-issuer-controller-manager -c manager
```

| Condition message pattern | Likely cause |
| --- | --- |
| P10CR CP certReqId | Server returned an unexpected identifier; adjust `p10crResponseCertReqId` or use default |
| Response protection / trust | Wrong CMP trust anchors or unexpected signer |
| Response sender does not name the configured recipient | The server answers under a different name than `spec.protocol.recipient`. Set the recipient to the name the server puts in its responses. Attribute order does not matter, so only a genuine difference in attributes or values causes this |
| Transaction deadline / maximum polls | Server queue too slow; increase `spec.transaction` limits |
| Connection refused / timeout | Wrong URL, network policy or server down |
| HTTP redirect rejected | Endpoint redirects; use the final CMP URL |
| Recorded CMP transaction enrolls a different request | The `CMPTransaction` was edited or corrupted; delete it so the request enrolls again |
| `transactionIdInUse`, or `badRequest` naming a `GENERATED` end entity | The controller resent an enrollment the server had already accepted, so its response was lost. No second certificate was issued. cert-manager enrolls again under a new transaction identifier |

The transaction `Phase` column tells you where a request stopped. `Enrolling` means the enrollment is unanswered and will be resent unchanged. `Polling` means the server asked for `pollReq`. `Confirming` means the certificate is issued and recorded, and only the confirmation is outstanding. `Issued` means the certificate is confirmed and recorded, and no further CMP traffic will be sent.

## EJBCA client mode

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Refused after first success | End entity in GENERATED state | Reset end entity status to NEW before repeat enrollment |
| Subject mismatch | Signature mode enrolls bootstrap DN only | Match Certificate SAN/CN to registered end entity or use PBM with correct profile |
| Wrong protection | Alias authentication modules | Confirm alias uses HMAC for PBM and EndEntityCertificate for signature |

## Nokia NCM

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Header protection failed with vendor client | Missing end-entity cert in P10CR extraCerts | Use cmp-issuer layout or fix client |
| pkiConf verification failed before fix | Signer not retained | Upgrade to a build with confirmation signer retention |
| Pinning certReqId -1 | NCM returns 0 | Omit pin or set `p10crResponseCertReqId: 0` |

## Requests stay pending and nothing happens

A `CertificateRequest` that never gains an `Approved` condition, with no error anywhere and no CMP
traffic, means cert-manager is not permitted to approve requests for this issuer type. Its built-in
approver acts only on issuer types it holds explicit permission for, and reports nothing when it lacks
that permission.

```bash
kubectl get certificaterequest -n <namespace>
```

An `APPROVED` column that is empty rather than `True` confirms it.

The installation grants this permission by default, so reaching this state usually means one of:

* cert-manager runs under a different ServiceAccount or namespace than the binding names. Check the
  subject against your installation and set `certManagerApproval.serviceAccountName` and
  `certManagerApproval.namespace`.
* `certManagerApproval.create` was set to `false`, or the ClusterRole was removed from the manifest.
* Approval is delegated to approver-policy and no `CertificateRequestPolicy` covers these requests.

Inspect what is bound:

```bash
kubectl get clusterrolebinding -o wide | grep cert-manager-approver
```

To confirm the diagnosis before changing RBAC, approve one request by hand with
`cmctl approve <name> -n <namespace>` and watch it proceed.

[Installation](../installation.md#cert-manager-approval) covers the settings.

## Denied or unapproved requests

cmp-issuer sends **no** CMP message for unapproved or denied `CertificateRequest` resources. Verify cert-manager approval policies and `CertificateRequest` conditions.

Note: issuer-lib treats a freshly denied request as neither approved nor denied when `Ready=False` with reason `Denied` instead of a `Denied` condition type. Denied requests still produce no CMP traffic in practice.

## Invalid protection tests

Wrong PSK or invalid response signer fail closed: no certificate accepted and no TLS Secret written.

## HTTP warning

An HTTP issuer emits a one-time Ready warning about missing transport confidentiality. This is expected, not an error.

## Related pages

* [Tested PKIs](../interoperability/tested-pkis.md)
* [Known limitations](../known-limitations.md)
* [Transaction recovery](../guide/transaction-recovery.md)
