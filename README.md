# Tender Management System — security improvement lab

This repository contains a legacy Java/JSP tender and bidding project and a small, real defensive-code research workflow. Its purpose is to identify, document, and progressively correct application security problems in a maintainer-controlled project copy.

**Status:** Educational, incomplete source. Several JSP pages import `com.hit.*` servlet, DAO, utility and bean classes that are **not present** in this repository. The security helper classes can compile, but the complete legacy application cannot be built, deployed, or penetration-tested end to end from the published source. Do **not** treat it as production-secure or use it with real tender, customer, or financial data.

## Implemented in this repository

- **Authorization guard improvement:** 23 admin/vendor JSP pages use null-safe role checks, stop rendering after rejection, and no longer read the session password. The missing login backend may still store a password and must be audited separately.
- **Output encoding:** Two request-parameter reflections use a tested Java `HtmlEscaper` helper for HTML text output.
- **Sensitive actions:** Bid accept/reject and notice removal are now POST forms with synchronizer tokens. `MutatingActionFilter` enforces admin sessions, POST and per-session CSRF tokens for those three servlet routes. Backend servlet implementations are missing; their POST behavior and object-level authorization cannot yet be verified.
- **Static security scanner:** `security/scan.mjs` recursively inspects JSP source for null-unsafe role checks, session password use, direct HTML reflection, and selected state-changing GET entry points.
- **Regression tests:** Nine Node tests check the analyzer, role guards, protected forms and filter mappings; a Java smoke test exercises the output encoder, and four Maven/JUnit tests verify security helpers.
- **CI:** GitHub Actions compiles Java security helpers, runs tests, and blocks new scanner findings. The tracked baseline currently contains no matching JSP signatures; this is **not** a system-wide security certification.
- **Reporting and disclosure:** [SECURITY.md](SECURITY.md) documents scope and how to report vulnerabilities safely.

## Run the security checks

Requires Node.js 22 or newer, **JDK 21** (including the Java compiler), and **Apache Maven**. No credentials, deployment or database access are required.

```sh
node --test security/*.test.mjs
node security/scan.mjs --check
node security/scan.mjs --json
mvn -q test
```

`--check` exits nonzero when new signatures appear beyond `security/baseline.json`. It does **not** prove that all routes are secure. For the changes and remaining work, see [the assessment](security/ASSESSMENT.md).

## Security research scope

The work is limited to the maintainer's source code and synthetic examples. No unauthorized scanning, exploitation, access to third-party systems, or active malware work is involved. Security reports may be submitted to the contact in `SECURITY.md`; this repository does not offer a public bug bounty.

## Legacy source provenance

The uploaded JSP and SQL files match publicly available files in [shashirajraja/Tender-Management-System](https://github.com/shashirajraja/Tender-Management-System). Other GitHub copies also contain identical files, so the exact source of this manual upload is not established. The maintainer's original work in this repository is the documented security-improvement layer, not authorship of the legacy Java/JSP system. No express reuse license was found at that reference repository's root during this assessment; do not import its missing backend files or claim original authorship without confirming the applicable rights and attribution.

**Next engineering steps:** recover the missing Java backend sources; ensure the login handler never stores passwords in sessions; implement or verify POST handlers and object-level authorization for bid decisions; encode all other untrusted display fields by context; audit database queries; and run integration tests against a controlled local deployment. Those items are **not yet verified**.
