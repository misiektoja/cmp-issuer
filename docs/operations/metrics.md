# Metrics

The controller serves Prometheus metrics on port 8443. Alongside the standard controller-runtime, Go
runtime and client-go families, cmp-issuer publishes what its own enrollments did.

Every series carries the same three labels:

| Label | Values |
| --- | --- |
| `issuer_kind` | `CMPIssuer` or `CMPClusterIssuer` |
| `issuer` | `namespace/name` for a `CMPIssuer`, `name` for a `CMPClusterIssuer` |
| `operation` | `enrollment` or `renewal` |

`operation` separates the first issuance of a certificate from a renewal. cert-manager stamps
each `CertificateRequest` with the revision it will become, so anything past the first is a renewal. A
`CertificateRequest` written by hand carries no revision and counts as an enrollment. A renewal can send
another P10CR or a KUR. This metric label describes certificate lifecycle intent rather than the CMP body.
See [Renewal with P10CR or KUR](../guide/renewal-and-kur.md).

## What is published

| Metric | Type | Labels beyond the three above | Meaning |
| --- | --- | --- | --- |
| `cmp_issuer_enrollment_total` | counter | `result` is `issued` or `failed` | Completed attempts. A wait for a server that has not answered is not an attempt |
| `cmp_issuer_enrollment_duration_seconds` | histogram | `result` | Time from recording the CMP transaction to its outcome, including every poll and confirmation wait |
| `cmp_issuer_enrollment_failures_total` | counter | `failure`, `classification` | Failures by the CMP failure that ended them and whether that failure is retried |
| `cmp_issuer_enrollment_polls_total` | counter | none | Waits for a server that accepted a request but has not returned or confirmed the certificate |
| `cmp_issuer_enrollment_confirmations_total` | counter | `confirmation` is `Explicit` or `Implicit` | Completed enrollments by whether the server required `certConf` |

`failure` carries one name from a fixed vocabulary, so a server cannot mint new metric series and an
alert can match one exact name. A server-reported failure is named by its most security-relevant CMP
failure bit, checked in the order `badMessageCheck`, `signerNotTrusted`, `notAuthorized`, `badPOP`,
`badCertTemplate`, `badAlg`, `transactionIdInUse`, `badRequest`, `systemUnavail` and `systemFailure`,
with `unknownStatus` when none of these bits is set. A response that sets several bits is counted
once under the first matching name and the complete bit list appears in the `CMP enrollment failed`
log line. Failures cmp-issuer detects itself keep their own names, such as `wrongAuthority` or
`certReqIdMismatch`, plus `issuerConfiguration` for a failure that never reached the server and
`unclassified` for one that carries no CMP failure information. `classification` is `Permanent`,
`Retryable`, `Security` or `Unknown`, matching the `classification` field of the `CMP enrollment
failed` log line, which also names the protocol step the failure came from.

The duration is measured from the `CMPTransaction` record, not from the current reconcile, so an
enrollment a server queued for ten minutes is observed as ten minutes rather than as several short
reconciles. A retried failure is counted once per attempt.

## Example queries

Enrollment failure rate over the last hour, split by whether it was a renewal:

```promql
sum by (operation) (rate(cmp_issuer_enrollment_total{result="failed"}[1h]))
  / sum by (operation) (rate(cmp_issuer_enrollment_total[1h]))
```

Renewals that are failing, by cause, which is the query that tells you whether a CA changed a profile:

```promql
sum by (issuer, failure) (increase(cmp_issuer_enrollment_failures_total{operation="renewal"}[24h]))
```

The 95th percentile enrollment time per issuer, to catch a CA that has started queueing:

```promql
histogram_quantile(0.95, sum by (le, issuer) (rate(cmp_issuer_enrollment_duration_seconds_bucket{result="issued"}[30m])))
```

Authentication failures, which usually mean a rotated shared secret or an expired signing
certificate:

```promql
sum by (issuer) (increase(cmp_issuer_enrollment_failures_total{failure="badMessageCheck"}[15m])) > 0
```

## Reaching the endpoint

Every scrape is authenticated with a `TokenReview` and authorized with a `SubjectAccessReview`, so the
scraping ServiceAccount needs the `cmp-issuer-metrics-reader` ClusterRole the installation creates:

```bash
kubectl create clusterrolebinding prometheus-cmp-issuer-metrics --clusterrole=cmp-issuer-metrics-reader --serviceaccount=monitoring:prometheus
```

Set `prometheus.enabled=true` to have the chart create a `ServiceMonitor`. By default the endpoint
presents a certificate the controller generates for `localhost`, which no scraper that checks the
server name can verify, so the `ServiceMonitor` skips verification. Set
`metrics.tls.certManager.enabled=true` to have cert-manager issue a certificate for the Service name
instead, and the `ServiceMonitor` verifies it. See [installation](../installation.md).

`metrics.secure=false` serves plain HTTP with no authentication, for a collector that cannot present a
token. Pair it with `networkPolicy.enabled=true`.
