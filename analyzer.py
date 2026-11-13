#!/usr/bin/env python3
"""
outbound-email-copy-spamtrap-word-analyzer
==========================================

Pre-deployment linter for cold email sequences. Scans subject lines and bodies
before templates are pushed to outbound engines such as Smartlead or Instantly,
and reports:

  * weighted spam-trigger words and pushy / deceptive tone   (rules/spam_words.json)
  * malformed, unclosed or unsupported merge tags and spintax
  * broken tracking pixels, malformed links, risky HTML
  * excessive capitalisation, punctuation and hidden characters

Every finding has a location (subject/body, line, column), a severity and a
remediation. Findings roll up into a 0-100 Spam Risk Score per email.

Usage (see README.md for the full reference):

    python analyzer.py sequence.json --platform smartlead
    python analyzer.py step1.txt --format json --output report.json
    python analyzer.py --subject "Quick idea for {{company_name}}" --body-file body.html

Standard library only. Python 3.9+.

DISCLAIMER & LIABILITY LIMITATION
---------------------------------
This software is provided "AS IS", without warranty of any kind. A low score is
not a deliverability guarantee: mailbox providers use reputation, authentication
(SPF/DKIM/DMARC), engagement and many signals this tool cannot see. The author
and dhRobin Systems accept no liability for deliverability failures, domain or
IP blacklisting, spam-filter actions, or risks arising from third-party CRM or
outbound platforms. The deployer is solely responsible for compliance with
outbound email law (e.g. CAN-SPAM, GDPR, CASL, PECR). See DISCLAIMER.md.

MIT License. Copyright (c) 2026 DH Robin (dhRobin Systems).
"""

from __future__ import annotations

import argparse
import bisect
import csv
import io
import json
import math
import os
import re
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

__version__ = "1.0.0"
TOOL_NAME = "outbound-email-copy-spamtrap-word-analyzer"
DEFAULT_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "spam_words.json")

# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
# Points contributed by structural (non-dictionary) findings.
SEVERITY_POINTS = {"info": 0.0, "low": 2.0, "medium": 5.0, "high": 10.0, "critical": 20.0}
# score = 100 * (1 - e^(-points / SCORE_SCALE)): 10 pts -> 25, 20 -> 44, 35 -> 63, 60 -> 82.
SCORE_SCALE = 35.0
SUBJECT_MULTIPLIER = 1.5  # subject lines weigh more with content filters
BANDS = ((80, "CRITICAL"), (60, "HIGH"), (40, "ELEVATED"), (20, "MODERATE"), (0, "LOW"))

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

RE_HTML_DETECT = re.compile(r"<\s*/?\s*(?:a|p|div|br|span|img|table|tr|td|b|strong|i|em|u|html|body|font|ul|ol|li|h[1-6])\b", re.I)
RE_HTML_BLOCKS = re.compile(r"<!--.*?-->|<style\b.*?</style\s*>|<script\b.*?</script\s*>|<head\b.*?</head\s*>", re.I | re.S)
RE_HTML_TAG = re.compile(r"<[^<>]*>")
RE_MACRO = re.compile(r"\{\{(.*?)\}\}")
RE_URL_TEXT = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.I)
RE_ANCHOR = re.compile(r"<a\b([^>]*)>(.*?)</a\s*>", re.I | re.S)
RE_ANCHOR_OPEN = re.compile(r"<a\b", re.I)
RE_ANCHOR_CLOSE = re.compile(r"</a\s*>", re.I)
RE_IMG = re.compile(r"<img\b", re.I)
RE_ATTR = re.compile(r"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s\"'=<>`]+)", re.S)
RE_TAG_TOKEN = re.compile(r"<\s*(/?)\s*([A-Za-z][A-Za-z0-9]*)\b[^<>]*?(/?)\s*>")
RE_FORBIDDEN_TAG = re.compile(r"<\s*(script|iframe|form|object|embed|video|audio|input|button|meta\s+http-equiv)\b", re.I)
RE_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\s*(?:;|\"|'|$)|color\s*:\s*(?:#fff(?:fff)?\b|white\b)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|\"|'|$)", re.I)
RE_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
RE_DECEPTIVE_PREFIX = re.compile(r"^\s*(re|fw|fwd)\s*:", re.I)
RE_VAR_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")
RE_SINGLE_BRACE = re.compile(r"\{([^{}\n]*)\}")
RE_WORD = re.compile(r"[A-Za-z][A-Za-z'’-]*")
RE_OPT_OUT = re.compile(
    r"unsubscribe|opt[\s-]?out|not interested|reply\s+[\"'“]?(?:stop|no|remove|unsubscribe)|"
    r"(?:rather|prefer)\s+not\s+(?:to\s+)?hear|let me know if (?:this|it)(?:'s| is)? not (?:relevant|a fit)|"
    r"(?:won['’]t|will not)\s+(?:follow\s+up|reach\s+out|email\s+you|contact\s+you|bother\s+you)|remove you|"
    r"close (?:the|your) file|stop (?:emailing|reaching out)",
    re.I,
)
RE_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
VOID_TAGS = {"br", "img", "hr", "meta", "link", "input", "col", "area", "base", "wbr", "source"}
OPTIONAL_CLOSE_TAGS = {"p", "li", "td", "tr", "th", "thead", "tbody", "option", "html", "body", "head"}
TRACKED_PAIR_TAGS = {"b", "strong", "i", "em", "u", "div", "span", "table", "ul", "ol", "font", "center", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote"}


# ---------------------------------------------------------------------------
# Errors and data model
# ---------------------------------------------------------------------------


class RulesError(Exception):
    """The rules file is missing or invalid."""


class InputError(Exception):
    """An input file or argument could not be read."""


@dataclass
class Finding:
    rule_id: str
    severity: str
    category: str
    message: str
    remediation: str
    part: str  # "subject" or "body"
    line: int
    column: int
    excerpt: str
    points: float = 0.0
    term: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "part": self.part,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "remediation": self.remediation,
            "excerpt": self.excerpt,
            "points": round(self.points, 2),
        }
        if self.term is not None:
            data["term"] = self.term
        return data


@dataclass
class EmailInput:
    subject: str
    body: str
    step: int = 1
    label: str = ""
    source: str = "<input>"


@dataclass
class EmailReport:
    email: EmailInput
    findings: List[Finding]
    score: int
    band: str
    status: str
    raw_points: float
    stats: Dict[str, Any]

    def counts(self) -> Dict[str, int]:
        result = {name: 0 for name in SEVERITIES}
        for f in self.findings:
            result[f.severity] += 1
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.email.label,
            "source": self.email.source,
            "step": self.email.step,
            "score": self.score,
            "band": self.band,
            "status": self.status,
            "raw_points": round(self.raw_points, 2),
            "counts": self.counts(),
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class AnalyzerOptions:
    platform: str = "generic"
    custom_fields: Sequence[str] = field(default_factory=list)
    ignore_rules: Sequence[str] = field(default_factory=list)
    compliance_checks: bool = True
    fail_threshold: int = 60
    fail_on_severity: str = "critical"
    max_links: int = 3
    max_words: int = 200
    min_words: int = 15
    max_subject_chars: int = 60


# ---------------------------------------------------------------------------
# Rules loading
# ---------------------------------------------------------------------------


@dataclass
class CompiledTerm:
    id: str
    term: str
    category: str
    weight: int
    applies_to: str
    suggestion: str
    regex: "re.Pattern[str]"


class Rules:
    """Validated, compiled view of rules/spam_words.json."""

    def __init__(self, data: Dict[str, Any], path: str = "<memory>") -> None:
        self.path = path
        self.version = str(data.get("version", "0"))
        problems: List[str] = []

        self.categories: Dict[str, Dict[str, str]] = data.get("categories") or {}
        if not isinstance(self.categories, dict) or not self.categories:
            problems.append("'categories' must be a non-empty object")

        self.terms: List[CompiledTerm] = []
        seen_ids = set()
        for index, raw in enumerate(data.get("terms") or []):
            where = f"terms[{index}]"
            if not isinstance(raw, dict):
                problems.append(f"{where} must be an object")
                continue
            term_id = str(raw.get("id", "")).strip()
            term = str(raw.get("term", "")).strip()
            category = raw.get("category")
            weight = raw.get("weight")
            match = raw.get("match", "phrase")
            applies_to = raw.get("applies_to", "any")
            if not term_id or term_id in seen_ids:
                problems.append(f"{where} has a missing or duplicate id ({term_id!r})")
            seen_ids.add(term_id)
            if not term:
                problems.append(f"{where} ({term_id}) has an empty term")
            if category not in self.categories:
                problems.append(f"{where} ({term_id}) uses unknown category {category!r}")
            if not isinstance(weight, int) or isinstance(weight, bool) or not 1 <= weight <= 10:
                problems.append(f"{where} ({term_id}) weight must be an integer 1-10")
                continue
            if applies_to not in ("any", "subject", "body"):
                problems.append(f"{where} ({term_id}) applies_to must be any, subject or body")
            if match == "regex":
                pattern = raw.get("pattern")
                if not pattern:
                    problems.append(f"{where} ({term_id}) regex terms need a 'pattern'")
                    continue
            elif match == "phrase":
                pattern = phrase_pattern(term)
            else:
                problems.append(f"{where} ({term_id}) match must be 'phrase' or 'regex'")
                continue
            flags = 0 if raw.get("case_sensitive") else re.I
            try:
                compiled = re.compile(pattern, flags)
            except re.error as exc:
                problems.append(f"{where} ({term_id}) has an invalid regex: {exc}")
                continue
            self.terms.append(
                CompiledTerm(term_id, term, str(category), weight, applies_to, str(raw.get("suggestion", "")), compiled)
            )

        self.safe_acronyms = {str(a).upper() for a in data.get("safe_acronyms", [])}
        self.url_shorteners = {str(s).lower() for s in data.get("url_shorteners", [])}

        self.placeholder_patterns: List[Tuple[str, "re.Pattern[str]", str]] = []
        for raw in data.get("placeholder_patterns", []):
            try:
                flags = 0 if raw.get("case_sensitive") else re.I
                self.placeholder_patterns.append((raw["id"], re.compile(raw["pattern"], flags), raw.get("message", "Placeholder left in copy")))
            except (KeyError, re.error) as exc:
                problems.append(f"placeholder_patterns entry is invalid: {exc}")

        self.foreign_syntaxes: List[Tuple[str, "re.Pattern[str]", str]] = []
        for raw in data.get("foreign_merge_syntaxes", []):
            try:
                self.foreign_syntaxes.append((raw["name"], re.compile(raw["pattern"]), raw.get("example", "")))
            except (KeyError, re.error) as exc:
                problems.append(f"foreign_merge_syntaxes entry is invalid: {exc}")

        self.platforms: Dict[str, Dict[str, Any]] = data.get("platforms") or {}
        if "generic" not in self.platforms:
            problems.append("'platforms' must define at least 'generic'")

        if problems:
            raise RulesError(f"Invalid rules file {path}:\n  - " + "\n  - ".join(problems))


def phrase_pattern(term: str) -> str:
    """Whole-word, whitespace-tolerant pattern; apostrophes match ' and ’."""
    parts = [re.escape(p).replace("'", "['’]") for p in term.split()]
    return r"(?<![\w$%])" + r"\s+".join(parts) + r"(?![\w%])"


def load_rules(path: Optional[str] = None) -> Rules:
    rules_path = path or DEFAULT_RULES_PATH
    try:
        with open(rules_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise RulesError(f"Rules file not found: {rules_path}") from exc
    except json.JSONDecodeError as exc:
        raise RulesError(f"Rules file is not valid JSON ({rules_path}): {exc}") from exc
    if not isinstance(data, dict):
        raise RulesError(f"Rules file must contain a JSON object: {rules_path}")
    return Rules(data, rules_path)


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------


class Doc:
    """A text part with offset -> (line, column) mapping."""

    def __init__(self, part: str, text: str) -> None:
        self.part = part
        self.text = text
        self.line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]

    def loc(self, offset: int) -> Tuple[int, int]:
        offset = max(0, min(offset, len(self.text)))
        index = bisect.bisect_right(self.line_starts, offset) - 1
        return index + 1, offset - self.line_starts[index] + 1

    def excerpt(self, offset: int, width: int = 140) -> str:
        line, _ = self.loc(offset)
        start = self.line_starts[line - 1]
        end = self.text.find("\n", start)
        content = self.text[start : end if end != -1 else len(self.text)].strip()
        return content if len(content) <= width else content[: width - 1] + "…"


def mask_spans(text: str, spans: Iterable[Tuple[int, int]]) -> str:
    """Replace characters in spans with spaces, keeping newlines so offsets and lines stay aligned."""
    chars = list(text)
    for start, end in spans:
        for i in range(start, min(end, len(chars))):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def is_html(text: str) -> bool:
    return bool(RE_HTML_DETECT.search(text or ""))


def visible_text(raw: str, html_mode: bool) -> str:
    """Raw text with tags, macros and URLs blanked out (same length as raw)."""
    spans: List[Tuple[int, int]] = []
    if html_mode:
        spans += [m.span() for m in RE_HTML_BLOCKS.finditer(raw)]
        spans += [m.span() for m in RE_HTML_TAG.finditer(raw)]
    spans += [m.span() for m in RE_MACRO.finditer(raw)]
    spans += [m.span() for m in RE_URL_TEXT.finditer(raw)]
    text = mask_spans(raw, spans)
    if html_mode:
        # Common entities would otherwise read as words ("&nbsp" -> "nbsp").
        text = re.sub(r"&(?:[a-z]+|#\d+);", lambda m: " " * len(m.group()), text, flags=re.I)
    return text


def parse_attrs(tag_text: str) -> Dict[str, str]:
    attrs: Dict[str, str] = {}
    for match in RE_ATTR.finditer(tag_text):
        value = match.group(2)
        if value[:1] in ("'", '"'):
            value = value[1:-1]
        attrs[match.group(1).lower()] = value
    return attrs


def root_host(host: str) -> str:
    """Naive registrable part (last two labels, three for common ccSLDs)."""
    labels = [label for label in host.lower().strip(".").split(".") if label]
    if len(labels) >= 3 and labels[-2] in {"co", "com", "org", "net", "ac", "gov", "edu"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_emoji(char: str) -> bool:
    code = ord(char)
    return (
        0x1F300 <= code <= 0x1FAFF
        or 0x2600 <= code <= 0x27BF
        or 0x1F000 <= code <= 0x1F2FF
        or 0x2B00 <= code <= 0x2BFF
    )


def normalize_var(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class Analyzer:
    """Rule engine. Create once, call analyze() per email."""

    def __init__(self, rules: Optional[Rules] = None, options: Optional[AnalyzerOptions] = None) -> None:
        self.rules = rules or load_rules()
        self.options = options or AnalyzerOptions()
        if self.options.platform not in self.rules.platforms:
            raise InputError(f"Unknown platform {self.options.platform!r}. Choose one of: {', '.join(sorted(self.rules.platforms))}")
        if self.options.fail_on_severity not in SEVERITY_RANK and self.options.fail_on_severity != "none":
            raise InputError(f"fail_on_severity must be one of {', '.join(SEVERITIES)} or none")
        self.platform = self.rules.platforms[self.options.platform]
        self.known_vars = set(self.platform.get("variables", [])) | {f.strip() for f in self.options.custom_fields if f.strip()}
        self.ignored = {r.strip().upper() for r in self.options.ignore_rules if r.strip()}

    # -- public API ---------------------------------------------------------

    def analyze(self, email: EmailInput) -> EmailReport:
        subject_doc = Doc("subject", (email.subject or "").replace("\r\n", "\n").replace("\n", " ").strip("\n"))
        body_doc = Doc("body", (email.body or "").replace("\r\n", "\n"))
        html_mode = is_html(body_doc.text)
        findings: List[Finding] = []

        subject_visible = visible_text(subject_doc.text, False)
        body_visible = visible_text(body_doc.text, html_mode)

        self._check_subject(findings, subject_doc, email.step)
        self._check_terms(findings, subject_doc, subject_visible)
        self._check_terms(findings, body_doc, body_visible)
        for doc, visible in ((subject_doc, subject_visible), (body_doc, body_visible)):
            self._check_macros(findings, doc)
            self._check_placeholders(findings, doc)
            self._check_encoding(findings, doc, visible)
        self._check_caps(findings, body_doc, body_visible)
        self._check_punctuation(findings, body_doc, body_visible)
        link_count = self._check_links(findings, body_doc, html_mode, email.step)
        if subject_doc.text and RE_URL_TEXT.search(subject_doc.text):
            self._add(findings, "SUBJ_LINK", "high", "formatting", "Subject line contains a URL.", "Remove links from the subject line.", subject_doc, RE_URL_TEXT.search(subject_doc.text).start())
        pixel_count = self._check_images_and_pixels(findings, body_doc) if "<img" in body_doc.text.lower() else 0
        if html_mode:
            self._check_html(findings, body_doc)
        word_count = len(RE_WORD.findall(body_visible))
        self._check_length(findings, body_doc, word_count)
        if self.options.compliance_checks:
            self._check_compliance(findings, body_doc)

        findings.sort(key=lambda f: (0 if f.part == "subject" else 1, f.line, f.column, -SEVERITY_RANK[f.severity]))
        raw_points = sum(f.points for f in findings)
        score = score_from_points(raw_points)
        stats = {
            "format": "html" if html_mode else "text",
            "words": word_count,
            "subject_chars": len(subject_doc.text),
            "links": link_count,
            "tracking_pixels": pixel_count,
            "merge_tags": len(RE_MACRO.findall(subject_doc.text + "\n" + body_doc.text)),
        }
        return EmailReport(email, findings, score, band_for(score), self._status(score, findings), raw_points, stats)

    def analyze_many(self, emails: Iterable[EmailInput]) -> List[EmailReport]:
        return [self.analyze(email) for email in emails]

    # -- helpers ------------------------------------------------------------

    def _add(self, findings: List[Finding], rule_id: str, severity: str, category: str, message: str, remediation: str,
             doc: Doc, offset: int, points: Optional[float] = None, term: Optional[str] = None) -> None:
        if rule_id.upper() in self.ignored:
            return
        line, column = doc.loc(offset)
        findings.append(
            Finding(rule_id, severity, category, message, remediation, doc.part, line, column, doc.excerpt(offset),
                    SEVERITY_POINTS[severity] if points is None else points, term)
        )

    def _status(self, score: int, findings: List[Finding]) -> str:
        gate = self.options.fail_on_severity
        if score >= self.options.fail_threshold or (
            gate != "none" and any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK[gate] for f in findings)
        ):
            return "FAIL"
        if score >= 20 or any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK["medium"] for f in findings):
            return "WARN"
        return "PASS"

    # -- 1. Subject line ----------------------------------------------------

    def _check_subject(self, findings: List[Finding], doc: Doc, step: int) -> None:
        text = doc.text
        if not text.strip():
            if step <= 1:
                self._add(findings, "SUBJ_EMPTY", "high", "formatting", "First email in the sequence has no subject line.",
                          "Write a short, specific subject (3-7 words). Blank subjects are only normal for threaded follow-ups.", doc, 0)
            return
        prefix = RE_DECEPTIVE_PREFIX.match(text)
        if prefix:
            if step <= 1:
                self._add(findings, "SUBJ_DECEPTIVE_PREFIX", "high", "deceptive",
                          f"Subject starts with '{prefix.group(1)}:' on a first-touch email, faking a prior conversation.",
                          "Remove the Re:/Fwd: prefix. Mailbox providers and recipients treat fake reply threads as deceptive.", doc, prefix.start(1))
            else:
                self._add(findings, "SUBJ_MANUAL_REPLY_PREFIX", "info", "deceptive",
                          f"Follow-up subject manually starts with '{prefix.group(1)}:'.",
                          "Leave the follow-up subject blank so the platform threads it as a genuine reply.", doc, prefix.start(1))
        if len(text) > self.options.max_subject_chars:
            self._add(findings, "SUBJ_TOO_LONG", "low", "formatting",
                      f"Subject is {len(text)} characters (limit {self.options.max_subject_chars}).",
                      "Shorten to under ~60 characters so it is not truncated on mobile.", doc, self.options.max_subject_chars)
        letters = [c for c in visible_text(text, False) if c.isalpha()]
        if len(letters) >= 5 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
            self._add(findings, "SUBJ_ALL_CAPS", "high", "formatting", "Subject line is (almost) all capitals.",
                      "Use sentence case or lowercase; all-caps subjects are a strong spam signal.", doc, 0)
        emojis = [i for i, c in enumerate(text) if is_emoji(c)]
        if emojis:
            self._add(findings, "SUBJ_EMOJI", "medium" if len(emojis) > 1 else "low", "formatting",
                      f"Subject contains {len(emojis)} emoji.", "Remove emoji from cold-email subject lines.", doc, emojis[0])
        excl = re.search(r"!+|\?{2,}", text)
        if excl:
            self._add(findings, "SUBJ_EXCESS_PUNCTUATION", "medium", "formatting",
                      "Subject contains an exclamation mark or repeated question marks.",
                      "Remove exclamation marks and repeated punctuation from the subject.", doc, excl.start())

    # -- 2. Weighted spam dictionary ----------------------------------------

    def _check_terms(self, findings: List[Finding], doc: Doc, visible: str) -> None:
        if not visible.strip():
            return
        matches: List[Tuple[int, int, CompiledTerm]] = []
        for term in self.rules.terms:
            if term.applies_to != "any" and term.applies_to != doc.part:
                continue
            for m in term.regex.finditer(visible):
                if m.end() > m.start():
                    matches.append((m.start(), m.end(), term))
        # Longest match wins when phrases overlap ("100% free" beats "100%" and "free").
        matches.sort(key=lambda x: (-(x[1] - x[0]), x[0]))
        taken: List[Tuple[int, int]] = []
        kept: List[Tuple[int, int, CompiledTerm]] = []
        for start, end, term in matches:
            if any(start < t_end and end > t_start for t_start, t_end in taken):
                continue
            taken.append((start, end))
            kept.append((start, end, term))
        kept.sort(key=lambda x: x[0])

        occurrences: Dict[str, int] = {}
        multiplier = SUBJECT_MULTIPLIER if doc.part == "subject" else 1.0
        for start, end, term in kept:
            if term.id.upper() in self.ignored:
                continue
            n = occurrences.get(term.id, 0)
            occurrences[term.id] = n + 1
            points = term.weight * multiplier * (0.5 ** n)  # repeats add diminishing weight
            severity = "high" if term.weight >= 8 else "medium" if term.weight >= 5 else "low"
            label = self.rules.categories.get(term.category, {}).get("label", term.category)
            matched = doc.text[start:end]
            self._add(findings, f"SPAM_TERM:{term.id}", severity, term.category,
                      f"{label}: \"{matched}\" (weight {term.weight}{', in subject' if doc.part == 'subject' else ''}).",
                      term.suggestion or "Rephrase without this term.", doc, start, points=points, term=term.term)

    # -- 3. Merge tags, spintax and placeholders ----------------------------

    def _check_macros(self, findings: List[Finding], doc: Doc) -> None:
        text = doc.text
        if not text:
            return
        platform_name = self.options.platform
        # CSS blocks and HTML comments legitimately contain braces; never treat them as merge tags.
        consumed: List[Tuple[int, int]] = [m.span() for m in RE_HTML_BLOCKS.finditer(text)]

        for m in re.finditer(r"\{\{\{|\}\}\}", mask_spans(text, consumed)):
            self._add(findings, "MACRO_TRIPLE_BRACE", "high", "macro", f"Triple brace '{m.group()}' around a merge tag.",
                      "Use exactly two braces: {{variable}}.", doc, m.start())

        for name, regex, example in self.rules.foreign_syntaxes:
            for m in regex.finditer(text):
                consumed.append(m.span())
                self._add(findings, "MACRO_FOREIGN_SYNTAX", "critical", "macro",
                          f"{name} '{m.group()}' will not be replaced by {platform_name} and will be sent literally.",
                          f"Convert to {platform_name} syntax, e.g. {self._example_tag()}.", doc, m.start())

        for m in RE_MACRO.finditer(text):
            if any(m.start() >= s and m.end() <= e for s, e in consumed):
                continue
            consumed.append(m.span())
            self._validate_macro(findings, doc, m)

        remaining = mask_spans(text, consumed)
        for m in re.finditer(r"\{\{[A-Za-z0-9_. -]*\}?", remaining):
            self._add(findings, "MACRO_UNCLOSED", "critical", "macro", "Merge tag opened with '{{' but never closed.",
                      "Close the tag with '}}' so the variable renders, e.g. {{first_name}}.", doc, m.start())
            consumed.append((m.start(), m.end()))
        for m in re.finditer(r"\}\}", mask_spans(text, consumed)):
            self._add(findings, "MACRO_UNOPENED", "critical", "macro", "Stray '}}' with no opening '{{'.",
                      "Add the missing '{{' or remove the stray braces.", doc, m.start())
            consumed.append((m.start(), m.end()))

        remaining = mask_spans(text, consumed)
        for m in RE_SINGLE_BRACE.finditer(remaining):
            inner = m.group(1)
            if "|" in inner:
                consumed.append(m.span())
                if not self.platform.get("supports_brace_spintax", True):
                    self._add(findings, "SPINTAX_PLATFORM_MISMATCH", "high", "macro",
                              f"Brace spintax '{m.group()}' is not supported by the {platform_name} profile.",
                              "Use {{RANDOM | option one | option two}} for this platform.", doc, m.start())
                options = inner.split("|")
                if any(not o.strip() for o in options):
                    self._add(findings, "SPINTAX_EMPTY_OPTION", "high", "macro", f"Spintax '{m.group()}' contains an empty option.",
                              "Remove the empty option (doubled or trailing '|').", doc, m.start())
            elif RE_VAR_NAME.match(inner.strip() or "-"):
                consumed.append(m.span())
                self._add(findings, "MACRO_SINGLE_BRACE", "critical", "macro",
                          f"'{m.group()}' uses single braces and will be sent literally.",
                          f"Use double braces: {{{{{inner.strip()}}}}}.", doc, m.start())
        for m in re.finditer(r"[{}]", mask_spans(text, consumed)):
            self._add(findings, "SPINTAX_UNBALANCED", "medium", "macro", f"Unbalanced brace '{m.group()}'.",
                      "Remove the stray brace or complete the spintax / merge tag.", doc, m.start())

    def _example_tag(self) -> str:
        variables = self.platform.get("variables") or ["first_name"]
        return "{{" + variables[0] + "}}"

    def _validate_macro(self, findings: List[Finding], doc: Doc, m: "re.Match[str]") -> None:
        raw_inner = m.group(1)
        inner = raw_inner.strip()
        platform_name = self.options.platform
        if not inner:
            self._add(findings, "MACRO_EMPTY", "critical", "macro", "Empty merge tag '{{}}'.",
                      "Put a variable name inside the braces or remove the tag.", doc, m.start())
            return
        if re.match(r"(?i)^random\s*\|", inner):
            options = [o.strip() for o in inner.split("|")[1:]]
            if not self.platform.get("supports_random_spintax", False):
                self._add(findings, "SPINTAX_PLATFORM_MISMATCH", "high", "macro",
                          f"{{{{RANDOM | ...}}}} spintax is not supported by the {platform_name} profile.",
                          "Use brace spintax {option one|option two} for this platform.", doc, m.start())
            if len([o for o in options if o]) < 2:
                self._add(findings, "SPINTAX_SINGLE_OPTION", "high", "macro", "RANDOM spintax has fewer than two options.",
                          "Provide at least two non-empty options separated by '|'.", doc, m.start())
            elif any(not o for o in options):
                self._add(findings, "SPINTAX_EMPTY_OPTION", "high", "macro", "RANDOM spintax contains an empty option.",
                          "Remove the empty option.", doc, m.start())
            return
        if "{" in inner or "}" in inner:
            self._add(findings, "MACRO_NESTED", "critical", "macro", f"Nested or malformed braces inside '{m.group()}'.",
                      "Use one flat tag such as {{first_name}}.", doc, m.start())
            return
        name = inner
        if "|" in inner:
            name = inner.split("|", 1)[0].strip()
            if not self.platform.get("allows_fallback", False):
                self._add(findings, "MACRO_FALLBACK_UNSUPPORTED", "medium", "macro",
                          f"'{m.group()}' uses fallback syntax that the {platform_name} profile does not declare.",
                          "Confirm your platform supports fallbacks, or use a plain tag and fill empty values in the lead list.", doc, m.start())
        if raw_inner != raw_inner.strip() and not self.platform.get("allows_whitespace", True):
            self._add(findings, "MACRO_WHITESPACE", "low", "macro", f"Whitespace inside '{m.group()}'.",
                      f"Remove the spaces: {{{{{name}}}}}.", doc, m.start())
        if re.search(r"[,;!?]", name) or len(name.split()) > 2:
            # Prose between '{{' and a later '}}': really an unclosed tag plus a stray closer.
            self._add(findings, "MACRO_UNCLOSED", "critical", "macro", "Merge tag opened with '{{' but never closed.",
                      "Close the tag right after the variable name, e.g. {{first_name}}.", doc, m.start())
            self._add(findings, "MACRO_UNOPENED", "critical", "macro", "Stray '}}' with no matching '{{'.",
                      "Add the missing '{{' or remove the stray braces.", doc, m.end() - 2)
            return
        if not RE_VAR_NAME.match(name):
            self._add(findings, "MACRO_INVALID_NAME", "critical", "macro",
                      f"'{name}' is not a valid variable name (letters, digits and underscores only).",
                      "Rename the variable, e.g. 'first-name' -> 'first_name', and match it to the lead list column.", doc, m.start())
            return
        if not self.platform.get("strict", False) or name in self.known_vars:
            return
        target = normalize_var(name)
        suggestion = next((v for v in sorted(self.known_vars) if normalize_var(v) == target), None)
        if suggestion:
            self._add(findings, "MACRO_CASE_MISMATCH", "critical", "macro",
                      f"'{{{{{name}}}}}' does not match the {platform_name} variable '{{{{{suggestion}}}}}'.",
                      f"Use {{{{{suggestion}}}}} exactly (variable names are case- and format-sensitive).", doc, m.start())
        else:
            self._add(findings, "MACRO_UNSUPPORTED", "high", "macro",
                      f"'{{{{{name}}}}}' is not a known {platform_name} variable or declared custom field.",
                      "Add it as a custom field in the lead list and pass it with --custom-fields, or fix the name.", doc, m.start())

    def _check_placeholders(self, findings: List[Finding], doc: Doc) -> None:
        masked = mask_spans(doc.text, [m.span() for m in RE_HTML_TAG.finditer(doc.text) if not re.match(r"<(?:insert|your|company|name)", m.group(), re.I)])
        for pid, regex, message in self.rules.placeholder_patterns:
            for m in regex.finditer(masked):
                self._add(findings, "PLACEHOLDER_LEFTOVER", "critical", "macro", f"{message}: '{doc.text[m.start():m.end()]}'.",
                          "Replace with real copy or a valid merge tag before sending.", doc, m.start(), term=pid)

    # -- 4. Formatting ------------------------------------------------------

    def _check_caps(self, findings: List[Finding], doc: Doc, visible: str) -> None:
        letters = [c for c in visible if c.isalpha()]
        if len(letters) >= 40:
            ratio = sum(c.isupper() for c in letters) / len(letters)
            if ratio > 0.3:
                self._add(findings, "CAPS_RATIO", "high" if ratio > 0.5 else "medium", "formatting",
                          f"{ratio:.0%} of letters in the body are capitals.",
                          "Write in sentence case; heavy capitalisation reads as shouting and raises filter scores.", doc, 0)
        shouting = [m for m in re.finditer(r"\b[A-Z][A-Z'’]{3,}\b", visible) if m.group().upper() not in self.rules.safe_acronyms]
        for m in shouting[:5]:
            self._add(findings, "CAPS_WORD", "low", "formatting", f"All-caps word '{m.group()}'.",
                      "Use normal case; keep caps for genuine acronyms (add them to safe_acronyms in the rules file).", doc, m.start())
        if len(shouting) > 5:
            self._add(findings, "CAPS_WORD", "low", "formatting", f"{len(shouting) - 5} more all-caps words.",
                      "Use normal case throughout.", doc, shouting[5].start())

    def _check_punctuation(self, findings: List[Finding], doc: Doc, visible: str) -> None:
        for m in re.finditer(r"[!?]{2,}", visible):
            self._add(findings, "PUNCT_REPEATED", "medium", "formatting", f"Repeated punctuation '{m.group()}'.",
                      "Use a single full stop or question mark.", doc, m.start())
        bangs = [m.start() for m in re.finditer(r"!", visible)]
        if len(bangs) >= 2:
            self._add(findings, "PUNCT_EXCLAMATION_COUNT", "medium" if len(bangs) >= 3 else "low", "formatting",
                      f"{len(bangs)} exclamation marks in the body.", "Keep at most one; zero is better in cold email.", doc, bangs[0])
        for m in re.finditer(r"[$€£]{2,}|[*#~=_]{4,}|[>]{3,}|[-]{5,}", visible):
            self._add(findings, "PUNCT_SYMBOL_RUN", "medium", "formatting", f"Symbol run '{m.group()}'.",
                      "Remove decorative symbol runs.", doc, m.start())
        non_space = [c for c in visible if not c.isspace()]
        if len(non_space) >= 80:
            punct = sum(1 for c in non_space if unicodedata.category(c).startswith(("P", "S")))
            ratio = punct / len(non_space)
            if ratio > 0.12:
                self._add(findings, "PUNCT_RATIO", "medium", "formatting", f"Punctuation and symbols are {ratio:.0%} of the body text.",
                          "Simplify formatting; aim for plain sentences.", doc, 0)

    def _check_encoding(self, findings: List[Finding], doc: Doc, visible: str) -> None:
        for m in RE_ZERO_WIDTH.finditer(doc.text):
            self._add(findings, "ENCODING_HIDDEN_CHAR", "high", "formatting",
                      f"Invisible character U+{ord(m.group()):04X} in the text.",
                      "Remove invisible characters; filters treat them as an evasion technique.", doc, m.start())
            break  # one finding per part is enough
        for m in re.finditer(r"\w+", visible):
            word = m.group()
            scripts = set()
            for ch in word:
                if ch.isalpha():
                    name = unicodedata.name(ch, "")
                    scripts.add("LATIN" if name.startswith("LATIN") else name.split(" ")[0])
            if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
                self._add(findings, "ENCODING_HOMOGLYPH", "high", "formatting", f"Word '{word}' mixes Latin with Cyrillic/Greek letters.",
                          "Retype the word with plain Latin characters; look-alike letters are a filter-evasion signal.", doc, m.start())

    # -- 5. Links, images, tracking pixels, HTML ----------------------------

    def _check_links(self, findings: List[Finding], doc: Doc, html_mode: bool, step: int) -> int:
        text = doc.text
        urls: List[Tuple[str, int, bool]] = []  # (url, offset, from_href)
        anchor_spans: List[Tuple[int, int]] = []

        if html_mode:
            for m in RE_ANCHOR.finditer(text):
                anchor_spans.append(m.span())
                attrs_text, inner = m.group(1), m.group(2)
                if attrs_text.count('"') % 2 or attrs_text.count("'") % 2:
                    self._add(findings, "LINK_MALFORMED", "high", "links", "Anchor tag has unbalanced quotes around its attributes.",
                              "Fix the quotes, e.g. <a href=\"https://example.com\">.", doc, m.start())
                    continue
                attrs = parse_attrs(attrs_text)
                href = attrs.get("href")
                if href is None or not href.strip() or href.strip() == "#":
                    self._add(findings, "LINK_EMPTY_HREF", "high", "links", "Link has an empty, missing or '#' href.",
                              "Point the link at a real https URL or remove it.", doc, m.start())
                    continue
                href_offset = m.start() + 2 + attrs_text.find(href) if href in attrs_text else m.start()
                urls.append((href.strip(), href_offset, True))
                anchor_text = re.sub(r"<[^>]*>", "", inner).strip()
                shown = re.match(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/?#].*)?$", anchor_text, re.I)
                target = self._host(href)
                if shown and target and "{{" not in anchor_text and root_host(shown.group(1)) != root_host(target):
                    self._add(findings, "LINK_TEXT_MISMATCH", "high", "links",
                              f"Link text shows '{shown.group(1)}' but points to '{target}'.",
                              "Make the visible URL match the destination; mismatches are a phishing signal.", doc, m.start())
            opens = len(RE_ANCHOR_OPEN.findall(text))
            closes = len(RE_ANCHOR_CLOSE.findall(text))
            if opens > closes:
                last_open = list(RE_ANCHOR_OPEN.finditer(text))[-1].start()
                self._add(findings, "LINK_UNCLOSED_ANCHOR", "high", "links", f"{opens - closes} <a> tag(s) without a closing </a>.",
                          "Close every link with </a>; unclosed anchors can turn the rest of the email into a link.", doc, last_open)

        searchable = mask_spans(text, anchor_spans + ([m.span() for m in RE_HTML_TAG.finditer(text)] if html_mode else []))
        for m in RE_URL_TEXT.finditer(searchable):
            url = m.group().rstrip(".,;:!?)]}'\"")
            urls.append((url, m.start(), False))

        unique = set()
        for url, offset, from_href in urls:
            if url.lower().startswith(("mailto:", "tel:")):
                continue
            unique.add(url.lower())
            self._validate_url(findings, doc, url, offset, from_href)

        if len(unique) > self.options.max_links:
            self._add(findings, "LINK_COUNT", "medium", "links", f"{len(unique)} distinct links (limit {self.options.max_links}).",
                      "Cut links to one, or none in the first email; each link adds filter risk.", doc, urls[0][1] if urls else 0)
        elif unique and step <= 1:
            self._add(findings, "LINK_IN_FIRST_EMAIL", "low", "links", "First-touch email contains a link.",
                      "Consider removing links from step 1 and asking for a reply instead; it improves inbox placement.", doc, urls[0][1])
        return len(unique)

    @staticmethod
    def _host(url: str) -> Optional[str]:
        candidate = RE_MACRO.sub("macro", url.strip())
        if candidate.lower().startswith("www."):
            candidate = "https://" + candidate
        try:
            return (urlsplit(candidate).hostname or None)
        except ValueError:
            return None

    def _validate_url(self, findings: List[Finding], doc: Doc, url: str, offset: int, from_href: bool) -> None:
        if re.search(r"(?i)https?:/{1,3}(?:https?:|www\.)", url) and re.search(r"(?i)^https?://(?:https?:)", url):
            self._add(findings, "LINK_DOUBLE_SCHEME", "high", "links", f"URL has a doubled scheme: '{url}'.",
                      "Remove the duplicated 'https://'.", doc, offset)
            return
        if re.search(r"\s", url):
            self._add(findings, "LINK_MALFORMED", "high", "links", f"URL contains whitespace: '{url}'.",
                      "Remove spaces or encode them as %20.", doc, offset)
            return
        candidate = RE_MACRO.sub("macro", url)
        if from_href and not re.match(r"(?i)^[a-z][a-z0-9+.-]*:", candidate):
            self._add(findings, "LINK_MISSING_SCHEME", "medium", "links", f"href '{url}' has no scheme.",
                      "Start the href with https:// so every email client resolves it.", doc, offset)
            candidate = "https://" + candidate.lstrip("/")
        elif candidate.lower().startswith("www."):
            candidate = "https://" + candidate
        if re.match(r"(?i)^javascript:", candidate):
            self._add(findings, "LINK_JAVASCRIPT", "critical", "links", "javascript: URL in a link.",
                      "Remove script URLs; they are blocked and heavily penalised.", doc, offset)
            return
        try:
            parts = urlsplit(candidate)
            host = parts.hostname or ""
            _ = parts.port  # raises ValueError for malformed ports
        except ValueError:
            self._add(findings, "LINK_MALFORMED", "high", "links", f"URL could not be parsed: '{url}'.",
                      "Fix the URL syntax.", doc, offset)
            return
        if not host or not re.match(r"^[a-z0-9.-]+$", host) or ".." in host or "." not in host:
            if "macro" not in host:
                self._add(findings, "LINK_MALFORMED", "high", "links", f"URL has an invalid host: '{url}'.",
                          "Use a full, valid domain such as https://example.com/page.", doc, offset)
            return
        if parts.scheme.lower() == "http":
            self._add(findings, "LINK_INSECURE", "low", "links", f"Link uses http:// instead of https://: '{url}'.",
                      "Use https:// links.", doc, offset)
        if RE_IPV4.match(host):
            self._add(findings, "LINK_IP_HOST", "high", "links", f"Link points to a raw IP address: '{host}'.",
                      "Link to a domain name, never an IP address.", doc, offset)
        elif root_host(host) in self.rules.url_shorteners or host in self.rules.url_shorteners:
            self._add(findings, "LINK_SHORTENER", "high", "links", f"Public URL shortener '{host}'.",
                      "Use the full destination URL (or a branded link domain you own); public shorteners are widely blocklisted.", doc, offset)

    def _check_images_and_pixels(self, findings: List[Finding], doc: Doc) -> int:
        text = doc.text
        pixels = 0
        images = 0
        for m in RE_IMG.finditer(text):
            start = m.start()
            close = text.find(">", start)
            next_open = text.find("<", start + 1)
            malformed = close == -1 or (next_open != -1 and next_open < close)
            tag = text[start : (close + 1 if not malformed else (next_open if next_open != -1 else len(text)))]
            attrs = parse_attrs(tag)
            style = attrs.get("style", "").lower()
            width = attrs.get("width", "").strip().lower().replace("px", "")
            height = attrs.get("height", "").strip().lower().replace("px", "")
            src = attrs.get("src")
            is_pixel = width in ("0", "1") or height in ("0", "1") or bool(re.search(r"width\s*:\s*[01]px|height\s*:\s*[01]px", style)) \
                or bool(src and re.search(r"(?i)pixel|track|beacon|/open[/?.]|\bopen\.(?:gif|png)", src))
            kind = "PIXEL" if is_pixel else "IMG"
            if is_pixel:
                pixels += 1
            else:
                images += 1

            if malformed or tag.count('"') % 2 or tag.count("'") % 2:
                self._add(findings, f"{kind}_MALFORMED_TAG", "high", "tracking" if is_pixel else "html",
                          "Image tag is not closed or has unbalanced quotes." if is_pixel else "Image tag is malformed.",
                          "Close the tag and quote every attribute, e.g. <img src=\"https://...\" width=\"1\" height=\"1\" alt=\"\">.", doc, start)
                continue
            if src is None or not src.strip():
                self._add(findings, f"{kind}_NO_SRC", "high", "tracking" if is_pixel else "html",
                          "Tracking pixel has no src." if is_pixel else "Image has no src.",
                          "Set a valid https:// src or remove the tag.", doc, start)
                continue
            src = src.strip()
            if src.lower().startswith("data:"):
                self._add(findings, "IMG_BASE64", "high", "html", "Inline base64 (data:) image.",
                          "Host the image on an https URL or remove it; embedded images bloat the message and are filtered.", doc, start)
                continue
            if "{{" in src or "}}" in src:
                stripped = RE_MACRO.sub("", src)
                if "{{" in stripped or "}}" in stripped:
                    self._add(findings, f"{kind}_MACRO_ERROR", "critical", "tracking" if is_pixel else "html",
                              "Broken merge tag inside the image src.", "Fix the merge tag so the URL renders.", doc, start)
            host = self._host(src) if re.match(r"(?i)^(https?:)?//", src) else None
            if not host:
                self._add(findings, f"{kind}_INVALID_SRC", "high", "tracking" if is_pixel else "html",
                          f"Image src is not an absolute https URL: '{src[:80]}'.",
                          "Use an absolute https:// URL; relative or protocol-less src will not load in email clients.", doc, start)
            elif src.lower().startswith("http://"):
                self._add(findings, f"{kind}_INSECURE", "medium", "tracking" if is_pixel else "html",
                          "Image loads over http://.", "Serve the image over https://.", doc, start)
            elif src.startswith("//"):
                self._add(findings, f"{kind}_PROTOCOL_RELATIVE", "medium", "tracking" if is_pixel else "html",
                          "Image src is protocol-relative ('//...').", "Use an explicit https:// URL.", doc, start)
            if is_pixel and re.search(r"display\s*:\s*none|visibility\s*:\s*hidden", style):
                self._add(findings, "PIXEL_HIDDEN_STYLE", "low", "tracking", "Tracking pixel is hidden with CSS.",
                          "Hidden pixels may not load in some clients; size it 1x1 instead of hiding it.", doc, start)
            if not is_pixel and "alt" not in attrs:
                self._add(findings, "IMG_NO_ALT", "low", "html", "Image has no alt attribute.", "Add alt text.", doc, start)

        first = RE_IMG.search(text)
        if pixels:
            self._add(findings, "PIXEL_MANUAL_TRACKING", "medium", "tracking",
                      f"{pixels} manually embedded tracking pixel(s).",
                      "Outbound engines such as Smartlead and Instantly inject their own open tracking. Remove manual pixels, "
                      "and consider disabling open tracking for cold sequences.", doc, first.start() if first else 0)
        if pixels > 1:
            self._add(findings, "PIXEL_DUPLICATE", "medium", "tracking", f"{pixels} tracking pixels in one email.",
                      "Keep at most one pixel.", doc, first.start() if first else 0)
        if images:
            self._add(findings, "IMG_IN_COLD_EMAIL", "low" if images == 1 else "medium", "html", f"{images} image(s) in the email.",
                      "Plain-text style emails without images perform better for cold outreach.", doc, first.start() if first else 0)
        return pixels

    def _check_html(self, findings: List[Finding], doc: Doc) -> None:
        text = doc.text
        for m in RE_FORBIDDEN_TAG.finditer(text):
            self._add(findings, "HTML_FORBIDDEN_TAG", "critical", "html", f"<{m.group(1).lower()}> tag in an email.",
                      "Remove it. Scripts, forms, frames and media embeds are stripped or blocked by mailbox providers.", doc, m.start())
        for m in re.finditer(r"<(?!img\b)[a-z][^<>]*\bstyle\s*=\s*(\"[^\"]*\"|'[^']*')", text, re.I):
            if RE_HIDDEN_STYLE.search(m.group(1)):
                self._add(findings, "HTML_HIDDEN_TEXT", "high", "html", "Element styled to be invisible (hidden, zero-size or white text).",
                          "Remove hidden text; it is a classic filter-evasion signal.", doc, m.start())
        # Malformed tags: '<tag ...' with no closing '>' before the next '<' or the end.
        for m in re.finditer(r"<(/?[a-zA-Z][a-zA-Z0-9]*)\b[^<>]*(?=<|$)", text):
            if m.group(1).lower() == "img":
                continue  # reported by the image / pixel check
            self._add(findings, "HTML_MALFORMED_TAG", "high", "html", f"Tag '<{m.group(1)}' is never closed with '>'.",
                      "Add the missing '>'.", doc, m.start())
        stack: List[Tuple[str, int]] = []
        for m in RE_TAG_TOKEN.finditer(text):
            closing, name, self_closing = m.group(1), m.group(2).lower(), m.group(3)
            if name in VOID_TAGS or self_closing or name == "a":
                continue
            if not closing:
                if name in TRACKED_PAIR_TAGS or name in OPTIONAL_CLOSE_TAGS:
                    stack.append((name, m.start()))
                continue
            for i in range(len(stack) - 1, -1, -1):
                if stack[i][0] == name:
                    # Anything opened inside this element and not closed is implicitly cut off here.
                    for inner_name, inner_offset in stack[i + 1 :]:
                        if inner_name in TRACKED_PAIR_TAGS:
                            self._add(findings, "HTML_UNCLOSED_TAG", "medium", "html", f"<{inner_name}> is never closed.",
                                      f"Add </{inner_name}> before </{name}>.", doc, inner_offset)
                    del stack[i:]
                    break
            else:
                if name in TRACKED_PAIR_TAGS:
                    self._add(findings, "HTML_STRAY_CLOSING_TAG", "low", "html", f"Closing </{name}> without a matching opening tag.",
                              "Remove the stray closing tag.", doc, m.start())
        for name, offset in stack:
            if name in TRACKED_PAIR_TAGS:
                self._add(findings, "HTML_UNCLOSED_TAG", "medium", "html", f"<{name}> is never closed.",
                          f"Add </{name}>; unclosed formatting can bleed into signatures and footers.", doc, offset)

    # -- 6. Length and compliance -------------------------------------------

    def _check_length(self, findings: List[Finding], doc: Doc, words: int) -> None:
        if words > self.options.max_words:
            self._add(findings, "LENGTH_TOO_LONG", "low", "formatting", f"Body is {words} words (target under {self.options.max_words}).",
                      "Cut to the problem, one proof point and one question; long cold emails get fewer replies.", doc, 0)
        elif 0 < words < self.options.min_words:
            self._add(findings, "LENGTH_TOO_SHORT", "info", "formatting", f"Body is only {words} words.",
                      "Very short bodies with a link look automated; make sure there is a clear, human reason for writing.", doc, 0)
        elif words == 0:
            self._add(findings, "BODY_EMPTY", "critical", "formatting", "Email body is empty.", "Add body copy.", doc, 0)

    def _check_compliance(self, findings: List[Finding], doc: Doc) -> None:
        if doc.text.strip() and not RE_OPT_OUT.search(doc.text):
            self._add(findings, "COMPLIANCE_NO_OPT_OUT", "low", "compliance", "No opt-out or unsubscribe language detected.",
                      "Commercial email laws (e.g. CAN-SPAM) require a working opt-out. Confirm your platform adds an unsubscribe link, "
                      "or add a line such as 'If this isn't relevant, just let me know and I won't follow up.' "
                      "Disable this check with --no-compliance if the platform handles it.", doc, max(0, len(doc.text) - 1))


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------


def score_from_points(points: float) -> int:
    if points <= 0:
        return 0
    return max(0, min(100, int(round(100 * (1 - math.exp(-points / SCORE_SCALE))))))


def band_for(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "LOW"


# ---------------------------------------------------------------------------
# Input loading
# ---------------------------------------------------------------------------

SUBJECT_KEYS = ("subject", "email_subject", "subject_line")
BODY_KEYS = ("body", "email_body", "html", "html_body", "text", "text_body", "content", "message")
STEP_KEYS = ("step", "seq_number", "sequence_number", "order", "position")
CONTAINER_KEYS = ("emails", "sequence", "sequences", "steps", "templates", "sequence_steps", "data")


def _first(mapping: Dict[str, Any], keys: Sequence[str]) -> Optional[Any]:
    lowered = {str(k).lower(): v for k, v in mapping.items()}
    for key in keys:
        if key in lowered and lowered[key] is not None:
            return lowered[key]
    return None


def extract_emails(obj: Any, source: str, default_step: int = 1) -> List[EmailInput]:
    """Extract emails from flexible JSON shapes (lists, sequences, steps, A/B variants)."""
    emails: List[EmailInput] = []

    def visit(node: Any, step_hint: int, label_prefix: str) -> None:
        if isinstance(node, list):
            for index, item in enumerate(node):
                step = step_hint if step_hint > 0 else index + 1
                if isinstance(item, dict) and _first(item, STEP_KEYS) is None:
                    visit(item, index + 1 if step_hint <= 0 else step, label_prefix)
                else:
                    visit(item, step, label_prefix)
            return
        if not isinstance(node, dict):
            return
        explicit_step = _first(node, STEP_KEYS)
        step = int(explicit_step) if isinstance(explicit_step, (int, float, str)) and str(explicit_step).isdigit() else max(step_hint, 1)
        variants = _first(node, ("variants", "ab_variants", "versions"))
        if isinstance(variants, list) and variants:
            shared_subject = _first(node, SUBJECT_KEYS)
            for vi, variant in enumerate(variants):
                if not isinstance(variant, dict):
                    continue
                subject = _first(variant, SUBJECT_KEYS)
                body = _first(variant, BODY_KEYS)
                emails.append(EmailInput(str(subject if subject is not None else shared_subject or ""), str(body or ""), step,
                                         f"{label_prefix}step {step} variant {chr(65 + vi)}", source))
            return
        body = _first(node, BODY_KEYS)
        if body is not None and not isinstance(body, (dict, list)):
            subject = _first(node, SUBJECT_KEYS)
            name = node.get("name") or node.get("title")
            label = f"{label_prefix}step {step}" + (f" ({name})" if isinstance(name, str) and name else "")
            emails.append(EmailInput(str(subject or ""), str(body), step, label, source))
            return
        for key in CONTAINER_KEYS:
            child = _first(node, (key,))
            if isinstance(child, (list, dict)):
                name = node.get("name")
                prefix = f"{label_prefix}{name} › " if isinstance(name, str) and name and key in ("steps", "sequence") else label_prefix
                visit(child, 0, prefix)
                return

    visit(obj, default_step if not isinstance(obj, list) else 0, "")
    return emails


def parse_text_email(text: str, source: str, step: int) -> EmailInput:
    """'Subject: ...' on the first non-empty line is optional; the rest is the body."""
    lines = text.replace("\r\n", "\n").split("\n")
    subject = ""
    index = 0
    while index < len(lines) and not lines[index].strip():
        index += 1
    if index < len(lines) and re.match(r"(?i)^subject\s*:", lines[index]):
        subject = lines[index].split(":", 1)[1].strip()
        index += 1
        if index < len(lines) and not lines[index].strip():
            index += 1
        body = "\n".join(lines[index:])
    else:
        body = text
    return EmailInput(subject, body, step, f"step {step}", source)


def load_file(path: str, step: int = 1) -> List[EmailInput]:
    if path == "-":
        return [parse_text_email(sys.stdin.read(), "<stdin>", step)]
    if not os.path.isfile(path):
        raise InputError(f"Input file not found: {path}")
    name = os.path.basename(path)
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".eml":
            with open(path, "rb") as handle:
                message = BytesParser(policy=policy.default).parse(handle)
            part = message.get_body(preferencelist=("html", "plain"))
            body = part.get_content() if part is not None else ""
            return [EmailInput(str(message.get("subject", "")), body, step, f"step {step}", name)]
        with open(path, "r", encoding="utf-8-sig") as handle:
            content = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"Could not read {path}: {exc}") from exc

    if ext == ".json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise InputError(f"{path} is not valid JSON: {exc}") from exc
        emails = extract_emails(data, name, step)
        if not emails:
            raise InputError(f"No emails found in {path}. Expected objects with 'subject' and 'body' (see README).")
        return emails
    if ext == ".csv":
        reader = csv.DictReader(io.StringIO(content))
        emails = []
        for row_number, row in enumerate(reader, start=1):
            body = _first(row, BODY_KEYS)
            if body is None:
                raise InputError(f"{path}: CSV needs a 'body' column (or one of: {', '.join(BODY_KEYS)}).")
            row_step = _first(row, STEP_KEYS)
            s = int(row_step) if row_step and str(row_step).isdigit() else row_number
            emails.append(EmailInput(str(_first(row, SUBJECT_KEYS) or ""), str(body), s, f"row {row_number} (step {s})", name))
        if not emails:
            raise InputError(f"No rows found in {path}.")
        return emails
    return [parse_text_email(content, name, step)]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

COLORS = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m",
          "FAIL": "\033[1;31m", "WARN": "\033[1;33m", "PASS": "\033[1;32m", "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m"}


def summarize(reports: Sequence[EmailReport]) -> Dict[str, Any]:
    counts = {name: 0 for name in SEVERITIES}
    for report in reports:
        for name, value in report.counts().items():
            counts[name] += value
    worst = max((r.score for r in reports), default=0)
    statuses = [r.status for r in reports]
    return {
        "emails": len(reports),
        "worst_score": worst,
        "worst_band": band_for(worst),
        "average_score": round(sum(r.score for r in reports) / len(reports), 1) if reports else 0,
        "status": "FAIL" if "FAIL" in statuses else "WARN" if "WARN" in statuses else "PASS",
        "counts": counts,
    }


def build_json_report(reports: Sequence[EmailReport], options: AnalyzerOptions, rules: Rules, timestamp: bool = True) -> Dict[str, Any]:
    report = {
        "tool": TOOL_NAME,
        "version": __version__,
        "rules_version": rules.version,
        "platform": options.platform,
        "fail_threshold": options.fail_threshold,
        "fail_on_severity": options.fail_on_severity,
        "summary": summarize(reports),
        "results": [r.to_dict() for r in reports],
    }
    if timestamp:
        report["generated_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return report


def render_text(reports: Sequence[EmailReport], options: AnalyzerOptions, color: bool = False, min_severity: str = "info") -> str:
    def c(key: str, text: str) -> str:
        return f"{COLORS[key]}{text}{COLORS['reset']}" if color else text

    out: List[str] = []
    out.append(c("bold", f"{TOOL_NAME} v{__version__}") + f"  platform={options.platform}  fail_threshold={options.fail_threshold}")
    out.append("=" * 78)
    floor = SEVERITY_RANK[min_severity]
    for index, report in enumerate(reports, start=1):
        e = report.email
        out.append("")
        out.append(c("bold", f"[{index}] {e.source} › {e.label or 'email'}"))
        out.append(f"    Spam Risk Score: {c('bold', str(report.score))}/100  {report.band:<9} Status: {c(report.status, report.status)}"
                   f"   ({report.stats['format']}, {report.stats['words']} words, {report.stats['links']} links)")
        shown = [f for f in report.findings if SEVERITY_RANK[f.severity] >= floor]
        if not shown:
            out.append(c("dim", "    No findings at or above '" + min_severity + "'."))
            continue
        for f in shown:
            where = f"{f.part}:{f.line}:{f.column}"
            out.append(f"    {where:<14} {c(f.severity, f.severity.upper()):<{8 + (len(COLORS[f.severity]) + len(COLORS['reset']) if color else 0)}} "
                       f"{f.rule_id:<28} {f.message}")
            out.append(c("dim", f"    {'':<14} {'':<8} ↳ fix: {f.remediation}"))
            if f.excerpt:
                out.append(c("dim", f"    {'':<14} {'':<8}   > {f.excerpt}"))
    s = summarize(reports)
    out.append("")
    out.append("=" * 78)
    counts = ", ".join(f"{s['counts'][k]} {k}" for k in reversed(SEVERITIES))
    out.append(f"Summary: {s['emails']} email(s) · worst score {s['worst_score']} ({s['worst_band']}) · average {s['average_score']} · {counts}")
    out.append(f"Overall status: {c(s['status'], s['status'])}")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyzer.py",
        description="Lint cold email copy for spam triggers, broken merge tags, tracking pixels and risky formatting.",
        epilog="Exit codes: 0 = pass/warn, 1 = fail (score >= threshold or blocking severity), 2 = usage or input error.",
    )
    parser.add_argument("paths", nargs="*", help="Files to scan (.json, .csv, .txt, .md, .html, .eml) or '-' for stdin.")
    parser.add_argument("--subject", help="Subject line to scan (use with --body or --body-file).")
    parser.add_argument("--body", help="Body text to scan.")
    parser.add_argument("--body-file", help="Read the body from this file.")
    parser.add_argument("--step", type=int, default=1, help="Sequence step for single-email input (default 1).")
    parser.add_argument("--platform", default="generic", help="Merge-tag profile: generic, smartlead, instantly (default generic).")
    parser.add_argument("--custom-fields", default="", help="Comma-separated custom variables allowed in merge tags.")
    parser.add_argument("--rules", help="Path to an alternative rules JSON file.")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format (default text).")
    parser.add_argument("--output", "-o", help="Write the report to this file instead of stdout.")
    parser.add_argument("--fail-threshold", type=int, default=60, help="Fail when any email scores at or above this (default 60).")
    parser.add_argument("--fail-on-severity", default="critical", choices=SEVERITIES + ("none",),
                        help="Fail when any finding is at or above this severity (default critical).")
    parser.add_argument("--min-severity", default="info", choices=SEVERITIES, help="Hide findings below this severity in text output.")
    parser.add_argument("--ignore", default="", help="Comma-separated rule IDs to skip (e.g. COMPLIANCE_NO_OPT_OUT,SPAM_TERM:SW042).")
    parser.add_argument("--no-compliance", action="store_true", help="Skip the opt-out language check.")
    parser.add_argument("--max-links", type=int, default=3, help="Maximum distinct links before LINK_COUNT fires (default 3).")
    parser.add_argument("--max-words", type=int, default=200, help="Word count above which LENGTH_TOO_LONG fires (default 200).")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colours.")
    parser.add_argument("--no-timestamp", action="store_true", help="Omit generated_at from JSON (reproducible output).")
    parser.add_argument("--list-rules", action="store_true", help="Print the spam dictionary and exit.")
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None, stdout: Any = None) -> int:
    stream = stdout or sys.stdout
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        rules = load_rules(args.rules)
        if args.list_rules:
            for t in sorted(rules.terms, key=lambda t: (t.category, -t.weight, t.term)):
                stream.write(f"{t.id}  {t.category:<17} w={t.weight:<2} {t.term}\n")
            return EXIT_PASS
        options = AnalyzerOptions(
            platform=args.platform.lower(),
            custom_fields=[f for f in args.custom_fields.split(",") if f.strip()],
            ignore_rules=[r for r in args.ignore.split(",") if r.strip()],
            compliance_checks=not args.no_compliance,
            fail_threshold=args.fail_threshold,
            fail_on_severity=args.fail_on_severity,
            max_links=args.max_links,
            max_words=args.max_words,
        )
        analyzer = Analyzer(rules, options)
        emails: List[EmailInput] = []
        if args.body is not None or args.body_file:
            if args.body_file:
                try:
                    with open(args.body_file, "r", encoding="utf-8-sig") as handle:
                        body = handle.read()
                except OSError as exc:
                    raise InputError(f"Could not read {args.body_file}: {exc}") from exc
            else:
                body = args.body
            emails.append(EmailInput(args.subject or "", body, args.step, f"step {args.step}", "<arguments>"))
        elif args.subject is not None:
            emails.append(EmailInput(args.subject, "", args.step, f"step {args.step}", "<arguments>"))
        for path in args.paths:
            emails.extend(load_file(path, args.step))
        if not emails:
            parser.print_usage(sys.stderr)
            sys.stderr.write("error: provide at least one file, '-', or --subject/--body\n")
            return EXIT_USAGE
    except (RulesError, InputError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_USAGE

    reports = analyzer.analyze_many(emails)
    if args.format == "json":
        output = json.dumps(build_json_report(reports, options, rules, timestamp=not args.no_timestamp), indent=2, ensure_ascii=False) + "\n"
    else:
        use_color = not args.no_color and not args.output and hasattr(stream, "isatty") and stream.isatty() and os.environ.get("NO_COLOR") is None
        output = render_text(reports, options, color=use_color, min_severity=args.min_severity)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
        stream.write(f"Report written to {args.output} (status {summarize(reports)['status']}).\n")
    else:
        stream.write(output)
    return EXIT_FAIL if summarize(reports)["status"] == "FAIL" else EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
