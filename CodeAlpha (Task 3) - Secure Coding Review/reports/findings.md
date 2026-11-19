# Secure Coding Review — Findings Register

**Scope:** Synthetic, intentionally vulnerable local Flask demonstration. **Status:** Findings confirmed by source review; runtime tool outputs require local execution.

| ID | Severity (illustrative) | Issue | Evidence | Recommendation | Verification |
|---|---|---|---|---|---|
| V-01 | High | SQL injection | SQL concatenation in `/lookup` | Parameter placeholders | `test_lookup_parameterization` |
| V-02 | High | HTML injection / potential XSS | User input concatenated into HTML template | Autoescaping `.html` template | `test_html_escaping` |
| V-03 | Medium | Hardcoded application secret | Constant SECRET_KEY | Env/ephemeral secret | Manual config review |
| V-04 | Medium | Debug server enabled | `debug=True` | Disable debug in deployment | `test_debug_disabled` |
| V-05 | Low/Medium | Missing response hardening | No CSP/nosniff/referrer header | Set response headers | `test_security_headers` |

**Caution:** Severity is contextual and not a CVSS assessment. Some static-analysis alerts may be false positives or not detect all issues. Do not publish real secrets or customer data.
