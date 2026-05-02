# Real World Use Cases to Tune Rules On

Structured log of false positives (and true positives that fired noisily) observed
during real `lcs scan -p` use. Each entry should give a rule author enough to
either tighten the rule, add an exclusion, or accept the trade-off.

## Entry template

```
### YYYY-MM-DD — <one-line summary>
- **Source**: <URL or command that produced the content>
- **Content type**: <e.g. JSON, HTML, Markdown, plain text>
- **Verdict**: false positive | true positive (noisy) | ambiguous
- **Engine / Rule / Severity**: <engine> / <rule_name> / <severity>
- **Match**: `<literal text matched>`
- **Surrounding context**: <what the content actually was — paste the line or describe the structure>
- **Why FP**: <reasoning — why a human reviewer would not act on this>
- **Suggested adjustment**: <concrete rule change, exclusion, or threshold tweak>
- **Reporter / project**: <who hit it, in what project>
```

---

## 2026-05-02 — GitHub Releases API JSON: feature-description PR titles trip `data_exfiltration`

- **Source**: `curl -fsSL "https://api.github.com/repos/go-gitea/gitea/releases?per_page=20"`
- **Content type**: JSON (GitHub Releases API response, ~280 KB)
- **Verdict**: false positive
- **Engine / Rule / Severity**: simple / `data_exfiltration` / HIGH
- **Match**: `Add API endpoint to request` (fired twice — two separate releases mentioning the phrase)
- **Surrounding context**: The matches occur inside the JSON `body` field of release notes — Gitea's changelog routinely lists merged PRs by their titles, and "Add API endpoint to ..." is a common PR-title prefix for any project that exposes an HTTP API. The full match was likely something like `"* Add API endpoint to request a deferred resource (#NNNNN)"` — a feature-addition bullet, not an instruction.
- **Why FP**: The rule's intent is to catch instructions telling a model to *embed* sensitive data in a URL/request (an exfiltration directive). The literal phrase "Add API endpoint to request" in a changelog describes a feature shipped by the project; it is descriptive, not imperative-toward-the-model. A human reviewer reading release notes would never act on it.
- **Suggested adjustment**:
  1. Tighten the keyword pattern: require an imperative subject ("send", "POST", "include in URL", "embed ... in request") rather than the bare phrase "API endpoint to request", which collides with feature-description English.
  2. Or: gate this rule by surrounding context — suppress when the match sits inside a Markdown bullet/list item, a JSON `body`/`description`/`title` field, or a code-fence comment.
  3. Or: downgrade to MEDIUM until tightened — a HIGH on a phrase this generic creates alert fatigue and pushes users to bypass the scan, which is the opposite of the rule's goal.
- **Reporter / project**: `infra/gitea` — fetching upstream Gitea release notes to plan a 1.24.3 → 1.25.x version bump.

## 2026-05-02 — GitHub Releases API JSON: SHA-256 asset checksums trip `hidden_content`

- **Source**: same as above (`/repos/go-gitea/gitea/releases?per_page=20`)
- **Content type**: JSON (GitHub Releases API response)
- **Verdict**: false positive (high-volume noise — ~140 hits in a single response)
- **Engine / Rule / Severity**: simple / `hidden_content` / MEDIUM
- **Match**: 64-character lowercase hex strings, e.g. `f8cad4e09a813e724ef5c805b575a079b5163835c3c7acc30fa5e4902c59...`
- **Surrounding context**: Every release asset in GitHub's API response carries a SHA-256 digest as a hex string. With 20 releases × ~7 assets each, that's well over a hundred hex digests in one payload. The scanner is treating the hex as suspicious base64-encoded content.
- **Why FP**: Hex (charset `[0-9a-f]`) is a strict subset of base64 (`[A-Za-z0-9+/=]`), so a base64 detector that doesn't reject pure-hex strings will flag every checksum, UUID-without-dashes, git SHA, and content-addressed identifier on the internet. These are not "hidden content" — they are openly published integrity values, and they appear next to a `digest` / `sha256` / `checksum` field name that gives them away.
- **Suggested adjustment**:
  1. Reject pure-hex strings (charset is `[0-9a-fA-F]` only) from the base64 detector — they cannot encode arbitrary bytes the way real base64 does.
  2. Or: when the match's charset is hex AND the length is exactly 32/40/64/128 (common digest sizes), classify as a digest and skip.
  3. Or: when the match is the value of a JSON key matching `/(sha\d*|digest|checksum|hash|etag|commit|sha)/i`, skip.
- **Reporter / project**: `infra/gitea` — same fetch as above.

### Cross-cutting note (both findings)

The GitHub Releases API is a high-value source for any agent doing version-bump work. Both rules above firing on the same response means the *combined* signal-to-noise on this endpoint is currently bad enough that a user is forced to either bypass the scan or `--disable` rules per-call. Worth treating "GitHub Releases API JSON" as a benchmark fixture for tuning passes.
