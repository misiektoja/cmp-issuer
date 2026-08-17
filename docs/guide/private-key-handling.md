# cert-manager private-key handling

cmp-issuer integrates with cert-manager external issuers. Private-key access policy differs between P10CR today and planned CRMF operations.

## P10CR: no workload private-key access

For P10CR initial enrollment cert-manager signs a PKCS #10 CSR with the workload private key and passes only the CSR bytes to the external issuer.

cmp-issuer:

* Forwards the signed CSR in P10CR
* Never reads the workload private key
* Never reads cert-manager's staging private-key Secret
* Does not interpret `cert-manager.io/private-key-secret-name`

The end-to-end suite covers this boundary: a crafted annotation pointing at a sentinel Secret leaves that Secret unchanged while enrollment still succeeds.

RBAC reinforces the boundary. The controller ClusterRole grants no default Secret read access in workload namespaces. Only explicitly authorized issuer credential namespaces are readable.

## Annotation is not authorization

`cert-manager.io/private-key-secret-name` names where cert-manager stores the workload key. It is not permission for the external issuer to read that Secret. Future CRMF support must not treat the annotation alone as sufficient authorization.

## Future CRMF and IR

Initial Registration with CRMF requires proof of possession over the workload private key. A future design must validate the owning `Certificate`, revision, issuer reference, expected Secret state, owner references, labels, CSR signature and public-key equality before reading only `tls.key`.

IR and true KUR remain **Planned**. See [P10CR renewal and KUR roadmap](renewal-and-kur.md).

## Related pages

* [Threat model](../security/threat-model.md)
* [Credential Secret access](../operations/secret-access.md)
* [Enrollment](enrollment.md)
