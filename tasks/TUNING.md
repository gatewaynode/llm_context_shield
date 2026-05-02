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

## 2026-05-02 — OpenTofu docs HTML: zero-width spaces in rendered docs trip `hidden_content`

- **Source**: `curl -fsSL "https://opentofu.org/docs/language/state/encryption/"`
- **Content type**: HTML (Docusaurus-rendered documentation page, ~430 KB)
- **Verdict**: false positive (high-volume noise — 25+ HIGH hits in a single page)
- **Engine / Rule / Severity**: simple / `hidden_content` / HIGH
- **Match**: `U+200B` (zero-width space), single codepoints scattered through the body at byte offsets 47105, 47642, 48597, 50240, 50880, 51642, 82990, 90703, 90913, 101619, 117264, 128840, 163861, 164046, 174213, 180156, 185621, 233959, 246383, 254043, 335725, 335915, 342630, 350701, 417562, ...
- **Surrounding context**: Docusaurus (and similar static-site generators) inject U+200B into rendered HTML for word-break hints inside long identifiers, code samples, breadcrumb separators, and search-index targets. They are placed by the framework, not by content authors, and a browser renders them invisibly. The OpenTofu docs site (built with Docusaurus) carries dozens per page on long technical documents.
- **Why FP**: Zero-width characters in *user-authored* content (markdown, comments, prompts) are a real exfiltration / steganography signal and HIGH is correct there. But in *framework-rendered* output, they are routine layout padding. A HIGH per-codepoint fires N times on a single page, drowning the alert log and pushing users to disable the rule wholesale — which then loses the signal in user content.
- **Suggested adjustment**:
  1. Detect HTML content (sniff `<!doctype html`, `<html`, or `Content-Type: text/html` if upstream passes it). For HTML, suppress U+200B inside `<code>`, `<pre>`, navigation elements, and known SSG class-name hints (`.menu`, `.breadcrumb`, `.token`).
  2. Or: switch from per-codepoint HIGH to a single per-document finding ("N zero-width characters detected in HTML body") with severity scaled by *density per KB*. A documentation page with 25 ZWS in 430 KB is 0.06/KB; an exfiltration payload typically has them clustered in a single short string.
  3. Or: when content type is HTML, downgrade isolated ZWS to LOW; keep HIGH only when ZWS are adjacent to other suspicious markers (long base64, hex sequences, or unusual unicode in close proximity).
- **Reporter / project**: `infra/gitea` — fetching OpenTofu state-encryption docs to verify the `TF_ENCRYPTION` JSON shape before adopting state encryption for per-agent token storage.

## 2026-05-02 — OpenTofu docs HTML: URL paths and example KMS resource paths trip `hidden_content` base64 detector

- **Source**: same as above (`opentofu.org/docs/language/state/encryption/`)
- **Content type**: HTML
- **Verdict**: false positive
- **Engine / Rule / Severity**: simple / `hidden_content` / MEDIUM
- **Match**: Several "Suspicious base64-encoded content" hits, including:
  - `id/locations/global/keyRings/ringid/cryptoKeys/keyid` (a GCP KMS resource-path example used to illustrate the `gcp_kms` key provider config)
  - `/docs/language/settings/backends/azurerm/` (an internal docs site URL path)
  - `com/opentofu/opentofu/tree/main/internal/encryption/keyprovider/...` and `.../method/encryption/...` (GitHub source-tree URLs cited in the docs)
  - `11/website/docs/language/state/encryption` (a versioned docs path)
- **Surrounding context**: All matches are URL fragments or example resource identifiers that happen to be long, contain only `[A-Za-z0-9/]`, and lack obvious word boundaries that would tip a heuristic off. They appear inside `<a href="...">` attributes, code samples, and prose like "see the example at github.com/opentofu/opentofu/...".
- **Why FP**: The base64 detector is keying on charset + length without considering structure. URL paths, file paths, and KMS/AWS-style resource ARNs are visually similar to base64 but are not encoded payloads — they are addressing strings, often present in the rendered DOM via `href` attributes. A reviewer reading the page sees clickable links, not encoded bytes.
- **Suggested adjustment**:
  1. Skip matches whose surrounding text contains `/` density > 1/8 chars — paths and URLs almost always exceed this; real base64 almost never does.
  2. Or: when the match begins/ends inside an HTML attribute value (`href=`, `src=`, `data-*`), suppress.
  3. Or: when the match contains substrings that are common path components (`/tree/`, `/blob/`, `/docs/`, `keyRings/`, `cryptoKeys/`, `arn:`, `projects/`, `locations/`), classify as a path identifier and skip.
- **Reporter / project**: `infra/gitea` — same fetch as above.

### Cross-cutting note (technical docs sites)

Docusaurus / Hugo / MkDocs documentation sites for security-adjacent topics (encryption, IAM, KMS) reliably trip both the ZWS rule (framework-injected layout) and the base64 rule (URL paths to source repos and resource-identifier examples). For an agent doing infrastructure research — exactly the audience most likely to be reading such docs — the current rules force a near-mandatory bypass. Worth a benchmark fixture: "vendor SSG-rendered HTML for an IaC topic page."
