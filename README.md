# Tender Management System — security improvement lab

This repository contains a legacy Java/JSP tender and bidding project and a small, real defensive-code research workflow. Its purpose is to identify, document, and progressively correct application security problems in code that the maintainer owns.

**Status:** Educational, incomplete source. Several JSP pages import `com.hit.*` servlet, DAO, utility and bean classes that are **not present** in this repository. The project therefore cannot currently be compiled, deployed, or penetration-tested end to end from the published source. Do **not** treat it as production-secure or use it with real tender, customer, or financial data.

## Implemented in this repository

- **Authorization guard improvement:** 23 admin/vendor JSP pages now compare expected roles without dereferencing a missing session value. Unauthorized requests redirect and `return` before the remainder of those pages renders. These are page-level checks, not a verified backend authorization system.
- **Static security scanner:** `security/scan.mjs` inspects JSP source for null-unsafe role checks, session password use, direct HTML reflection, and state-changing GET links.
- **Regression tests:** `security/scan.test.mjs` verifies the analyzer and checks role guards on each protected JSP.
- **CI:** GitHub Actions runs tests and detects **new** scanner findings relative to a committed, auditable baseline. Existing findings are intentionally visible and are not considered resolved.
- **Reporting and disclosure:** [SECURITY.md](SECURITY.md) documents scope and how to report vulnerabilities safely.

## Run the security checks

Requires Node.js 22 or newer; no credentials, deployment or database access are required.

```sh
node --test security/*.test.mjs
node security/scan.mjs --check
node security/scan.mjs --json
```

`--check` exits nonzero when the source contains findings not recorded in `security/baseline.json`. It does **not** mean the existing findings are safe. For the current findings and remediation priority, see [the assessment](security/ASSESSMENT.md).

## Security research scope

The work is limited to the maintainer's source code and synthetic examples. No unauthorized scanning, exploitation, access to third-party systems, or active malware work is involved. Security reports may be submitted to the contact in `SECURITY.md`; this repository does not offer a public bug bounty.

**Next engineering steps:** recover the missing Java backend sources; replace password-bearing session state; move bid approvals and notice removals to server-authorized POST handlers with CSRF protection; context-encode untrusted output; and run integration tests against a controlled local deployment. Those items are **not yet implemented**.
