# What this changes

<!-- What the change does and why. Link the issue it closes. -->

## Validation

<!-- Which of these you ran, and anything that failed. -->

- [ ] `make test`
- [ ] `make lint`
- [ ] `make test-e2e`, for a controller or e2e change
- [ ] `make docs-build`, for a documentation change
- [ ] `make helm-lint`, for a chart change
- [ ] Exercised against a real CMP server, for a protocol or controller change

<!-- A protocol or controller change is not verified by the test suites alone. Name the server and
     the operation you ran, without endpoint details or credentials. -->

## Documentation and release notes

- [ ] User-facing behavior is documented under `docs/`
- [ ] `RELEASE_NOTES.md` carries an entry, or the change is not user facing

## Anything a reviewer should know

<!-- Trade-offs, follow-up work, or parts you are unsure about. -->

<!-- Never include credentials, private keys, full CSRs, protected CMP messages or production
     endpoint details in a pull request. -->
