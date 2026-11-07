# Focused security assessment — 8 November 2026

## Scope and method

Inspected the public repository's JSP source, session-authorization guards, and visible servlet links. Added deterministic static-analysis signatures and tested them against synthetic snippets. No production service, customer account, database or third-party target was probed. The original repository does not contain the Java backend sources needed for compilation or integration tests.

## Confirmed changes

1. **23 protected JSP pages:** null-safe expected-role comparison; missing username causes rejection; `return` after redirect prevents the rest of the JSP from executing. The pages no longer read a password from the session.
2. **Two reflected request parameters:** output passes through a tested Java HTML text encoder.
3. **Three sensitive admin actions:** forms now POST a synchronizer token, and an annotated servlet filter checks method, admin session and token before forwarding to the action handler. This follows OWASP's synchronizer-token approach.
4. **Security scanner and tests:** repeatable source review with an empty current signature baseline, Java helper compilation, static form/filter checks and CI regression guard.

## Tracked findings addressed in JSP source

| Rule | Before | Now | What changed |
| --- | ---: | ---: | --- |
| AUTH-002 | 23 | 0 | Removed password-attribute reads from JSP access guards. |
| XSS-001 | 2 | 0 | Encoded the two directly reflected request parameters. |
| CSRF-001 | 3 | 0 | Replaced GET action links with POST forms and added a CSRF-checking servlet filter. |

These are **28 removed static signature matches**, not proof that 28 independent vulnerabilities have been fully resolved. The login backend could still retain passwords; missing action servlets might not implement POST or verify object ownership; many database-derived fields are still output by legacy JSP expressions. There may also be SQL injection, insecure password storage, missing backend authorization, sensitive logging, and deployment misconfiguration. Full review requires the missing source and a controlled runtime.

## Reproducibility

```sh
node --test security/*.test.mjs
node security/scan.mjs --check
```

At review time: seven Node tests and three Java JUnit tests pass, and all three Java security helper classes compile against Servlet API 3.0.1; no matching JSP signature findings remain. The original Java server-side functionality still cannot be end-to-end tested. This is a defensive learning exercise and **not** a claim of Anthropic Cyber Verification Program eligibility or approval.
