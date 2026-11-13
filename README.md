# outbound-email-copy-spamtrap-word-analyzer

A pre-deployment linter for cold email copy. It scans sequence subject lines and bodies **before** templates are pushed to outbound engines such as Smartlead or Instantly, and catches the mistakes that cost inbox placement and credibility:

- **Spam trigger words and tone**: a weighted dictionary of 180+ high-risk terms across 10 categories (false urgency, money hooks, guarantees, hard-sell CTAs, phishing-like phrasing, "this is not spam" disclaimers, cold-email cliches and more), plus fake `Re:` / `Fwd:` subjects.
- **Broken merge tags**: unclosed `{{first_name`, stray `}}`, single-brace `{first_name}`, empty tags, invalid names, wrong case (`{{firstName}}` vs `{{first_name}}`), unsupported variables, leftover `[Company]` placeholders, other tools' syntax (`*|FNAME|*`, `%FIRSTNAME%`, HubSpot tokens) and malformed spintax.
- **Tracking and formatting**: broken tracking-pixel tags, insecure or relative image sources, public URL shorteners, anchor text that shows a different domain than it links to, malformed hrefs, unclosed HTML, hidden text, all-caps, punctuation runs, invisible characters and look-alike letters.
- **Scoring and reporting**: a 0–100 **Spam Risk Score** per email, PASS / WARN / FAIL status, and line-by-line findings with a concrete fix for each, as a readable CLI report or JSON for pipelines.

Pure Python standard library. No API keys, no network calls: your copy never leaves the machine.

![Python](https://img.shields.io/badge/python-3.9%2B-3776AB)
![Dependencies](https://img.shields.io/badge/dependencies-0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Table of contents

1. [Installation](#installation)
2. [Quick start](#quick-start)
3. [Input formats](#input-formats)
4. [Platform profiles (Smartlead, Instantly, generic)](#platform-profiles)
5. [What it checks](#what-it-checks)
6. [Scoring model](#scoring-model)
7. [Output](#output)
8. [CLI reference](#cli-reference)
9. [Integration guide](#integration-guide)
10. [Customising the rules](#customising-the-rules)
11. [Using it as a library](#using-it-as-a-library)
12. [Testing](#testing)
13. [Limitations](#limitations)
14. [Disclaimer](#️-disclaimer--liability-limitation)
15. [License](#license)

---

## Installation

Requirements: **Python 3.9 or newer**. Nothing else.

```bash
git clone https://github.com/dhrobinsystems/outbound-email-copy-spamtrap-word-analyzer.git
cd outbound-email-copy-spamtrap-word-analyzer
python analyzer.py --version
```

Keep `analyzer.py` and the `rules/` folder together, or point to a rules file with `--rules`.

---

## Quick start

```bash
# A whole sequence exported or written as JSON
python analyzer.py examples/sample_sequence.json --platform smartlead --custom-fields sender_name,lead_id

# A single email: "Subject:" on the first line is optional
python analyzer.py step1.txt --platform instantly

# Inline copy
python analyzer.py --subject "Idea for {{company_name}}" --body-file body.html --platform smartlead

# Machine-readable report for a pipeline
python analyzer.py sequence.json --format json --output report.json
```

Example output (abridged):

```
[2] sample_sequence.json › Demo sequence (synthetic) › step 2
    Spam Risk Score: 83/100  CRITICAL  Status: FAIL   (text, 35 words, 0 links)
    body:1:4       CRITICAL MACRO_SINGLE_BRACE           '{first_name}' uses single braces and will be sent literally.
                            ↳ fix: Use double braces: {{first_name}}.
                              > Hi {first_name},
    body:3:40      CRITICAL MACRO_CASE_MISMATCH          '{{companyName}}' does not match the smartlead variable '{{company_name}}'.
                            ↳ fix: Use {{company_name}} exactly (variable names are case- and format-sensitive).
    body:3:80      CRITICAL PLACEHOLDER_LEFTOVER         Bracket placeholder left in the copy: '[Company]'.
                            ↳ fix: Replace with real copy or a valid merge tag before sending.
```

---

## Input formats

| Format | How it is read |
| --- | --- |
| `.json` | Flexible: a list of emails, `{"steps": [...]}`, `{"sequence": [...]}`, `{"sequences": [{"name", "steps"}]}`, `{"emails": [...]}`. Each email uses `subject` (or `email_subject`, `subject_line`) and `body` (or `email_body`, `html`, `text`, `content`, `message`). An optional `step` / `seq_number` / `order` sets the step number. A/B tests: `"variants": [{"subject", "body"}, ...]`. |
| `.csv` | Columns `subject` and `body` (same aliases), optional `step`. Handy for copy kept in a spreadsheet. |
| `.txt`, `.md`, `.html` | One email. If the first non-empty line starts with `Subject:`, it is the subject; the rest is the body. |
| `.eml` | One email; HTML part preferred, plain text otherwise. |
| `-` | Read one email from stdin (same rules as `.txt`). |
| `--subject` / `--body` / `--body-file` | Inline input. |

The **step number matters**: a blank subject or `Re:` is normal for a threaded follow-up (step 2+), but deceptive on a first touch.

Minimal JSON:

```json
{
  "steps": [
    { "step": 1, "subject": "Idea for {{company_name}}", "body": "Hi {{first_name}}, ..." },
    { "step": 2, "subject": "", "body": "Hi {{first_name}}, one more thought ..." }
  ]
}
```

---

## Platform profiles

Merge-tag validation depends on the engine. Choose a profile with `--platform`:

| Profile | Variables | Spintax | Strict |
| --- | --- | --- | --- |
| `generic` (default) | Any valid `{{name}}` | `{a\|b}` and `{{RANDOM \| a \| b}}` | No |
| `smartlead` | snake_case: `first_name`, `last_name`, `email`, `phone_number`, `company_name`, `website`, `location`, `linkedin_profile`, `company_url` | `{a\|b}` | Yes |
| `instantly` | camelCase: `firstName`, `lastName`, `email`, `companyName`, `website`, `phone`, `personalization`, `jobTitle`, `location`, `companyDomain`, `sendingAccountFirstName`, `accountSignature` | `{{RANDOM \| a \| b}}` | Yes |

In strict profiles, any variable that is not built-in or declared is reported. Declare your lead-list custom fields:

```bash
python analyzer.py sequence.json --platform smartlead --custom-fields sender_name,pain_point,industry_vertical
```

> The built-in variable lists are sensible defaults, not an official specification. Platforms add and rename fields. Check the variables available in your workspace and edit `platforms` in `rules/spam_words.json` to match.

---

## What it checks

### Spam dictionary (`SPAM_TERM:<id>`)

Terms are matched case-insensitively on whole words and phrases (`free` does not match `freedom`, `sale` does not match `sales`), across line breaks and with straight or curly apostrophes. HTML tags, URLs and merge tags are masked first, so `href="https://example.com/free-trial"` or `{{free_gift_code}}` never trigger. When phrases overlap, the longest wins (`100% free` is one hit, not three).

| Category | Examples | Typical weight |
| --- | --- | --- |
| `spam_disclaimer` | this is not spam, bulk email | 7–10 |
| `financial` | make money, extra income, $500 per day | 5–9 |
| `urgency` | act now, last chance, final notice | 5–9 |
| `free_offer` | 100% free, winner, claim your | 3–9 |
| `deceptive` | verify your account, as discussed, invoice attached | 5–8 |
| `sensitive` | pharmacy, casino, crypto | 5–9 |
| `guarantee` | guaranteed, risk-free, 30% off | 6–7 |
| `aggressive_sales` | buy now, click here, special offer | 4–8 |
| `hype` | once in a lifetime, game changer, 10x | 5–6 |
| `cliche_tone` | quick question, just following up, per my last email | 2–4 |

List every term with `python analyzer.py --list-rules`.

### Subject line

`SUBJ_DECEPTIVE_PREFIX` (fake `Re:`/`Fwd:` on step 1), `SUBJ_MANUAL_REPLY_PREFIX` (info on follow-ups), `SUBJ_EMPTY` (step 1), `SUBJ_ALL_CAPS`, `SUBJ_EMOJI`, `SUBJ_EXCESS_PUNCTUATION`, `SUBJ_TOO_LONG` (> 60 chars), `SUBJ_LINK`.

### Merge tags, spintax and placeholders

| Rule | Example | Severity |
| --- | --- | --- |
| `MACRO_UNCLOSED` | `Hi {{first_name,` | critical |
| `MACRO_UNOPENED` | `Hi first_name}},` | critical |
| `MACRO_SINGLE_BRACE` | `Hi {first_name},` | critical |
| `MACRO_EMPTY` | `{{}}` | critical |
| `MACRO_NESTED` | `{{ {{first_name}} }}` | critical |
| `MACRO_INVALID_NAME` | `{{first-name}}`, `{{first name}}` | critical |
| `MACRO_CASE_MISMATCH` | `{{firstName}}` on Smartlead → `{{first_name}}` | critical |
| `MACRO_FOREIGN_SYNTAX` | `*\|FNAME\|*`, `%FIRSTNAME%`, `<<First Name>>`, `${name}`, `{% if %}`, `{{ contact.firstname }}` | critical |
| `PLACEHOLDER_LEFTOVER` | `[Company]`, `TODO`, `XXX`, `lorem ipsum`, `<insert name>` | critical |
| `MACRO_UNSUPPORTED` | `{{favourite_colour}}` not in profile or custom fields | high |
| `MACRO_TRIPLE_BRACE` | `{{{first_name}}}` | high |
| `SPINTAX_EMPTY_OPTION` | `{Hi\|\|Hello}` | high |
| `SPINTAX_SINGLE_OPTION` | `{{RANDOM \| Hi}}` | high |
| `SPINTAX_PLATFORM_MISMATCH` | `{{RANDOM ...}}` on Smartlead, `{a\|b}` on Instantly | high |
| `MACRO_FALLBACK_UNSUPPORTED` | `{{first_name\|there}}` (verify platform support) | medium |
| `SPINTAX_UNBALANCED` | `{Hi\|Hello there` | medium |
| `MACRO_WHITESPACE` | `{{ first_name }}` (Smartlead profile) | low |

CSS inside `<style>` blocks and HTML comments is ignored, so braces there never cause false positives.

### Links

`LINK_JAVASCRIPT` (critical); `LINK_SHORTENER`, `LINK_IP_HOST`, `LINK_TEXT_MISMATCH`, `LINK_MALFORMED`, `LINK_DOUBLE_SCHEME`, `LINK_EMPTY_HREF`, `LINK_UNCLOSED_ANCHOR` (high); `LINK_MISSING_SCHEME`, `LINK_COUNT` (> 3 distinct links) (medium); `LINK_INSECURE`, `LINK_IN_FIRST_EMAIL` (low). `mailto:` and `tel:` links are ignored, trailing sentence punctuation is stripped, and merge tags inside URLs (`https://{{website}}/pricing`) are allowed.

### Tracking pixels and images

An `<img>` counts as a tracking pixel if it is 0–1 px wide or high (attribute or CSS), or its src looks like a tracker (`pixel`, `track`, `beacon`, `/open`).

| Rule | Meaning | Severity |
| --- | --- | --- |
| `PIXEL_MACRO_ERROR` | Broken merge tag inside the pixel URL | critical |
| `PIXEL_MALFORMED_TAG` | Tag not closed, or unbalanced quotes | high |
| `PIXEL_NO_SRC` / `PIXEL_INVALID_SRC` | Missing, empty, relative or non-URL src | high |
| `PIXEL_INSECURE` / `PIXEL_PROTOCOL_RELATIVE` | `http://` or `//` src | medium |
| `PIXEL_MANUAL_TRACKING` | Engines inject their own pixel; manual ones duplicate tracking | medium |
| `PIXEL_DUPLICATE` | More than one pixel | medium |
| `PIXEL_HIDDEN_STYLE` | `display:none` pixel may never load | low |

Regular images: `IMG_BASE64` (high), `IMG_MALFORMED_TAG`, `IMG_NO_SRC`, `IMG_INVALID_SRC` (high), `IMG_IN_COLD_EMAIL`, `IMG_NO_ALT` (low).

### HTML

`HTML_FORBIDDEN_TAG` (`script`, `iframe`, `form`, `object`, `embed`, media, inputs: critical), `HTML_HIDDEN_TEXT` (display:none, zero font size, white text: high), `HTML_MALFORMED_TAG` (high), `HTML_UNCLOSED_TAG` (medium), `HTML_STRAY_CLOSING_TAG` (low).

### Formatting, encoding, length and compliance

`CAPS_RATIO` (> 30 % capitals), `CAPS_WORD` (all-caps words, excluding `safe_acronyms` such as CRM, SaaS, GDPR), `PUNCT_REPEATED` (`!!`, `?!?`), `PUNCT_EXCLAMATION_COUNT`, `PUNCT_SYMBOL_RUN` (`$$`, `*****`), `PUNCT_RATIO`, `ENCODING_HIDDEN_CHAR` (zero-width characters), `ENCODING_HOMOGLYPH` (Latin mixed with Cyrillic/Greek look-alikes), `LENGTH_TOO_LONG` (> 200 words), `LENGTH_TOO_SHORT` (info), `BODY_EMPTY` (critical), `COMPLIANCE_NO_OPT_OUT` (low; no opt-out or unsubscribe language found; disable with `--no-compliance` if your platform appends one).

---

## Scoring model

1. Every finding carries **points**:
   - dictionary terms: their weight (1–10) × **1.5 in the subject line**, halved for each repeat of the same term in the same email (`free free free` = 3 + 1.5 + 0.75);
   - structural findings: low 2, medium 5, high 10, critical 20; info 0.
2. Points convert to a bounded score: `score = round(100 × (1 − e^(−points / 35)))`.

| Points | 10 | 20 | 35 | 60 | 100 |
| --- | --- | --- | --- | --- | --- |
| Score | 25 | 44 | 63 | 82 | 94 |

| Score | Band |
| --- | --- |
| 0–19 | LOW |
| 20–39 | MODERATE |
| 40–59 | ELEVATED |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

**Status** per email: **FAIL** if the score is at or above `--fail-threshold` (default 60) **or** any finding is at or above `--fail-on-severity` (default `critical`, so a broken merge tag always fails); **WARN** if the score is ≥ 20 or any finding is medium or higher; otherwise **PASS**. The overall status is the worst across all emails.

---

## Output

### Text (default)

Colour is used only on an interactive terminal (disable with `--no-color` or `NO_COLOR=1`). Filter noise with `--min-severity medium`.

### JSON (`--format json`)

```json
{
  "tool": "outbound-email-copy-spamtrap-word-analyzer",
  "version": "1.0.0",
  "rules_version": "1.0.0",
  "platform": "smartlead",
  "fail_threshold": 60,
  "fail_on_severity": "critical",
  "summary": {
    "emails": 3, "worst_score": 99, "worst_band": "CRITICAL", "average_score": 60.7, "status": "FAIL",
    "counts": { "info": 0, "low": 4, "medium": 9, "high": 8, "critical": 5 }
  },
  "results": [
    {
      "label": "Demo sequence (synthetic) › step 1",
      "source": "sample_sequence.json",
      "step": 1,
      "score": 99, "band": "CRITICAL", "status": "FAIL", "raw_points": 179.5,
      "counts": { "...": 0 },
      "stats": { "format": "html", "words": 32, "subject_chars": 52, "links": 2, "tracking_pixels": 1, "merge_tags": 3 },
      "findings": [
        {
          "rule_id": "SUBJ_DECEPTIVE_PREFIX", "severity": "high", "category": "deceptive",
          "part": "subject", "line": 1, "column": 1,
          "message": "Subject starts with 'Re:' on a first-touch email, faking a prior conversation.",
          "remediation": "Remove the Re:/Fwd: prefix. ...",
          "excerpt": "Re: URGENT - 100% FREE offer for {{company_name}}!!!",
          "points": 10.0
        }
      ]
    }
  ],
  "generated_at": "2026-01-01T00:00:00+00:00"
}
```

Use `--no-timestamp` for reproducible output (snapshot tests, diffs).

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All emails PASS or WARN |
| `1` | At least one email FAILs |
| `2` | Usage, input or rules-file error |

---

## CLI reference

```
python analyzer.py [paths ...] [options]

  paths                    .json, .csv, .txt, .md, .html, .eml files, or '-' for stdin
  --subject TEXT           subject line (inline input)
  --body TEXT              body text (inline input)
  --body-file PATH         body read from a file
  --step N                 sequence step for single-email input (default 1)
  --platform NAME          generic | smartlead | instantly (default generic)
  --custom-fields A,B      extra allowed merge variables
  --rules PATH             alternative rules JSON
  --format text|json       output format (default text)
  --output, -o PATH        write the report to a file
  --fail-threshold N       fail at or above this score (default 60)
  --fail-on-severity LVL   fail on any finding at/above: info|low|medium|high|critical|none (default critical)
  --min-severity LVL       hide lower-severity findings in text output
  --ignore IDS             skip rules, e.g. COMPLIANCE_NO_OPT_OUT,SPAM_TERM:SW042
  --no-compliance          skip the opt-out language check
  --max-links N            distinct links before LINK_COUNT (default 3)
  --max-words N            word count before LENGTH_TOO_LONG (default 200)
  --no-color               plain text output
  --no-timestamp           omit generated_at from JSON
  --list-rules             print the dictionary and exit
  --version
```

---

## Integration guide

The analyzer is a **gate between copywriting and launch**: write, lint, fix, then upload to the outbound engine.

```
Copy doc / sheet ──► export JSON or CSV ──► analyzer.py ──► PASS? ──► upload to Smartlead / Instantly
                                                   │
                                                   └── FAIL ──► fix the findings ──► re-run
```

### GitHub Actions (copy kept in a repository)

```yaml
name: Lint outbound copy
on: [pull_request]
jobs:
  lint-copy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Lint sequences
        run: |
          python tools/analyzer.py sequences/*.json --platform smartlead \
            --custom-fields sender_name,pain_point --fail-threshold 40 \
            --format json --output copy-report.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: copy-report
          path: copy-report.json
```

### Git pre-commit hook

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit
python analyzer.py sequences/*.json --platform instantly --min-severity medium || {
  echo "Copy lint failed: fix the findings above before committing."; exit 1; }
```

### Spreadsheet workflow

Keep copy in a sheet with `step`, `subject` and `body` columns, export as CSV, then run `python analyzer.py sequence.csv --platform smartlead`.

### Automation platforms (n8n, Make, CI runners)

Run the CLI from a command step and parse the JSON:

```bash
python /opt/tools/analyzer.py /tmp/sequence.json --platform smartlead --format json --no-timestamp
```

Gate the "push to outbound engine" step on `summary.status != "FAIL"`. Credentials for the outbound platform (e.g. `{{API_KEY}}`) belong in the automation tool's credential store; the analyzer itself never needs them.

### Before you launch

The analyzer checks **content**. Inbox placement also depends on sender reputation, SPF / DKIM / DMARC, domain age and warm-up, sending volume, list quality and engagement. Run a seed / inbox-placement test on a small batch before scaling any sequence.

---

## Customising the rules

`rules/spam_words.json` is plain data and is safe to edit:

```json
{
  "id": "SW182",
  "term": "limited spots",
  "category": "urgency",
  "weight": 6,
  "match": "phrase",
  "applies_to": "any",
  "suggestion": "Remove scarcity framing unless it is literally true."
}
```

- `match`: `phrase` (whole-word, whitespace-tolerant) or `regex` (add a `pattern`; set `"case_sensitive": true` if needed).
- `applies_to`: `any`, `subject` or `body`.
- `weight`: 1–10 (8+ reports as high, 5–7 medium, 1–4 low).
- Also editable: `categories`, `safe_acronyms`, `url_shorteners`, `placeholder_patterns`, `foreign_merge_syntaxes` and `platforms` (variables, `strict`, `allows_whitespace`, `allows_fallback`, spintax support).

The file is validated on load. Unknown categories, duplicate IDs, out-of-range weights and invalid regexes are all reported together. Keep your own copy and select it with `--rules path/to/rules.json`.

---

## Using it as a library

```python
from analyzer import Analyzer, AnalyzerOptions, EmailInput, load_rules

analyzer = Analyzer(load_rules(), AnalyzerOptions(platform="instantly", custom_fields=["painPoint"]))
report = analyzer.analyze(EmailInput(subject="Idea for {{companyName}}", body="Hi {{firstName}}, ...", step=1))

print(report.score, report.band, report.status)
for finding in report.findings:
    print(finding.part, finding.line, finding.column, finding.rule_id, finding.remediation)
```

---

## Testing

```bash
python -m unittest discover -s tests -v     # standard library
pytest -q                                   # if you prefer pytest
```

`tests/test_analyzer.py` covers the rules-file integrity and validation errors; whole-word, overlap, repeat and subject weighting; masking of URLs, tags and merge tags; every subject, merge-tag, spintax, placeholder, link, pixel, image, HTML, formatting, encoding, length and compliance rule; scoring bands and status gates; all input formats including A/B variants, CSV, `.eml` and stdin; CLI exit codes and JSON schema; robustness against malformed input, large bodies and Windows line endings; and a repository scan that fails if secrets or real email addresses are committed.

---

## Limitations

- It is a **content linter**, not a deliverability oracle. A score of 0 does not guarantee the inbox, and a flagged word is not always a problem in context. Treat findings as review prompts.
- The spam dictionary is curated from widely cited trigger lists and B2B outbound practice; no mailbox provider publishes its filters. Tune weights for your market and language (English only by default).
- Platform variable lists are defaults; verify them against your workspace.
- HTML checks are lint-level heuristics, not a full HTML parser.

---

## ⚠️ Disclaimer & Liability Limitation

Use at your own risk. The code, rules and scripts provided in this repository (`outbound-email-copy-spamtrap-word-analyzer`) are for educational and architectural demonstration purposes.

* **No Liability:** The author (Revenue Infrastructure Architect, dhRobin Systems) and dhRobin Systems assume no responsibility or liability for any direct, indirect, incidental, or consequential damages resulting from the use, misuse, or deployment of this tool, including email deliverability failures, domain or IP blacklisting, spam-filter actions, account suspensions, or risks arising from third-party CRM and outbound platforms.
* **No Warranty:** All software, rule dictionaries and Python modules are provided "AS IS" without warranty of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose, or non-infringement. A low Spam Risk Score is not a guarantee of inbox placement.
* **Production Testing Required:** Always validate sequences with seed or inbox-placement tests on a warmed-up, isolated sending domain before launching to live prospects or connecting production outbound accounts.
* **Third-Party APIs & Compliance:** Users are solely responsible for complying with the terms of service, sending limits, data privacy regulations (GDPR/CCPA), anti-spam laws (e.g. CAN-SPAM, CASL, PECR), and security policies of Smartlead, Instantly and any connected services, including honouring every unsubscribe request and reviewing every sequence before it is sent.

The full disclaimer is also available in [DISCLAIMER.md](https://github.com/dhrobinsystems/outbound-email-copy-spamtrap-word-analyzer/blob/main/DISCLAIMER.md).

## License

Released under the MIT License. Copyright (c) 2026 DH Robin (dhRobin Systems). See [LICENSE](https://github.com/dhrobinsystems/outbound-email-copy-spamtrap-word-analyzer/blob/main/LICENSE).
