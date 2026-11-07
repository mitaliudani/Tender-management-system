# Focused security assessment — 8 November 2026

## Scope and method

Inspected the public repository's JSP source, session-authorization guards, and visible servlet links. Added deterministic static-analysis signatures and tested them against synthetic snippets. No production service, customer account, database or third-party target was probed. The original repository does not contain the Java backend sources needed for compilation or integration tests.

## Confirmed changes

1. **23 protected JSP pages:** null-safe expected-role comparison; missing username/password-session values cause rejection; `return` after redirect prevents the rest of the JSP from executing in that request.
2. **Security scanner and tests:** repeatable source review of high-signal patterns, with a transparent baseline and CI regression check.

## Remaining findings (not fixed)

| Rule | Count | Risk | Remediation priority |
| --- | ---: | --- | --- |
| AUTH-002 | 23 | JSP pages still read `session.getAttribute("password")`; password-retaining sessions are inappropriate authorization state. | High — recover and change login/session backend, then remove references. |
| XSS-001 | 2 | User-controlled request parameters are embedded without HTML encoding. | High — context-aware HTML encoding and regression tests. |
| CSRF-001 | 3 | Notice removal and bid acceptance/rejection appear as links that initiate state changes via GET. | High — POST with server-verifiable CSRF tokens, server-side ownership/role checks and tests. |

There may be additional issues outside the scanner's four signatures, including SQL injection, insecure password storage, missing backend authorization, sensitive logging, and incomplete build/deployment configuration. A static signature scanner cannot establish their presence or absence without more source and runtime evidence.

## Reproducibility

```sh
node --test security/*.test.mjs
node security/scan.mjs --check
```

At review time: four tests pass; no new findings relative to `security/baseline.json`; 28 known findings remain. This is a defensive learning exercise and **not** a claim of Anthropic Cyber Verification Program eligibility or approval.
