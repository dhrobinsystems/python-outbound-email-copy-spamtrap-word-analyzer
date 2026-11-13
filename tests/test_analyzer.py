"""
tests/test_analyzer.py
======================

Test suite for outbound-email-copy-spamtrap-word-analyzer.

Runs with the standard library only:

    python -m unittest discover -s tests -v

and is also compatible with pytest (`pytest -q`). All sample copy, domains and
variables are synthetic; no real people, companies or credentials appear here.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import analyzer as A  # noqa: E402

RULES = A.load_rules()

CLEAN_SUBJECT = "Idea for {{company_name}}'s onboarding"
CLEAN_BODY = (
    "Hi {{first_name}},\n\n"
    "Teams like {{company_name}} usually lose a few hours a week cleaning duplicate CRM records before each import.\n\n"
    "We automate that check so new lists land clean. Would it be worth comparing notes next week?\n\n"
    "If this isn't relevant, just let me know and I won't follow up.\n\n"
    "Alex"
)


def run(subject="", body=CLEAN_BODY, step=1, **opts):
    options = A.AnalyzerOptions(**opts)
    return A.Analyzer(RULES, options).analyze(A.EmailInput(subject, body, step))


def rule_ids(report):
    return [f.rule_id for f in report.findings]


def has(report, rule_id):
    return any(f.rule_id == rule_id for f in report.findings)


def terms(report):
    return [f.term for f in report.findings if f.rule_id.startswith("SPAM_TERM:")]


class RulesFileTests(unittest.TestCase):
    """rules/spam_words.json is valid, consistent data."""

    def setUp(self):
        with open(A.DEFAULT_RULES_PATH, encoding="utf-8") as handle:
            self.data = json.load(handle)

    def test_loads_and_compiles(self):
        self.assertGreaterEqual(len(RULES.terms), 150)
        self.assertIn("generic", RULES.platforms)
        self.assertIn("smartlead", RULES.platforms)
        self.assertIn("instantly", RULES.platforms)

    def test_ids_unique_weights_in_range_categories_known(self):
        ids = [t["id"] for t in self.data["terms"]]
        self.assertEqual(len(ids), len(set(ids)))
        terms_lower = [t["term"].lower() for t in self.data["terms"]]
        self.assertEqual(len(terms_lower), len(set(terms_lower)), "duplicate terms")
        for t in self.data["terms"]:
            self.assertTrue(1 <= t["weight"] <= 10, t)
            self.assertIn(t["category"], self.data["categories"], t)
            self.assertTrue(t.get("suggestion"), f"{t['id']} has no remediation")
            self.assertIn(t["match"], ("phrase", "regex"))

    def test_every_category_is_used(self):
        used = {t["category"] for t in self.data["terms"]}
        self.assertEqual(used, set(self.data["categories"]))

    def _write(self, data):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(data, handle)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_invalid_rules_are_rejected_with_every_problem(self):
        bad = json.loads(json.dumps(self.data))
        bad["terms"] = [
            {"id": "X1", "term": "alpha", "category": "nope", "weight": 5, "match": "phrase"},
            {"id": "X1", "term": "beta", "category": "urgency", "weight": 11, "match": "phrase"},
            {"id": "X2", "term": "gamma", "category": "urgency", "weight": 5, "match": "regex", "pattern": "(unclosed"},
            {"id": "X3", "term": "delta", "category": "urgency", "weight": 5, "match": "fuzzy"},
        ]
        with self.assertRaises(A.RulesError) as ctx:
            A.load_rules(self._write(bad))
        message = str(ctx.exception)
        for needle in ("unknown category", "duplicate id", "weight must be", "invalid regex", "match must be"):
            self.assertIn(needle, message)

    def test_missing_and_malformed_rules_files(self):
        with self.assertRaises(A.RulesError):
            A.load_rules(os.path.join(ROOT, "rules", "does-not-exist.json"))
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        handle.write("{not json")
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        with self.assertRaises(A.RulesError):
            A.load_rules(handle.name)


class CleanBaselineTests(unittest.TestCase):
    def test_clean_email_scores_zero_and_passes(self):
        report = run(CLEAN_SUBJECT, CLEAN_BODY, platform="smartlead")
        self.assertEqual(report.findings, [], [f.to_dict() for f in report.findings])
        self.assertEqual(report.score, 0)
        self.assertEqual(report.band, "LOW")
        self.assertEqual(report.status, "PASS")
        self.assertEqual(report.stats["merge_tags"], 3)

    def test_threaded_follow_up_with_blank_subject_is_fine(self):
        self.assertFalse(has(run("", CLEAN_BODY, step=2), "SUBJ_EMPTY"))


class SpamTermTests(unittest.TestCase):
    def test_detects_terms_case_insensitively_with_location(self):
        report = run("Hello", "Line one.\nPlease ACT NOW before Friday.")
        finding = next(f for f in report.findings if f.term == "act now")
        self.assertEqual((finding.part, finding.line, finding.column), ("body", 2, 8))
        self.assertEqual(finding.severity, "high")
        self.assertIn("ACT NOW", finding.excerpt)

    def test_whole_word_matching_avoids_false_positives(self):
        report = run("Hello", "Our sales team values freedom, freelancers and the wholesale market.")
        self.assertEqual(terms(report), [])

    def test_phrase_spans_line_breaks_and_curly_apostrophes(self):
        self.assertIn("act now", terms(run("Hi", "Please act\nnow.")))
        self.assertIn("don't delete", terms(run("Hi", "Please don’t delete this.")))

    def test_longest_overlapping_phrase_wins(self):
        found = terms(run("Hi", "It is 100% free for your team."))
        self.assertEqual(found, ["100% free"])

    def test_repeated_terms_have_diminishing_weight(self):
        report = run("Hi", "free free free")
        points = [f.points for f in report.findings if f.term == "free"]
        self.assertEqual(points, [3.0, 1.5, 0.75])

    def test_subject_hits_weigh_more_than_body_hits(self):
        subject_hit = next(f for f in run("Urgent", "Hello there.").findings if f.term == "urgent")
        body_hit = next(f for f in run("Hello", "Urgent matter.").findings if f.term == "urgent")
        self.assertEqual(subject_hit.points, body_hit.points * A.SUBJECT_MULTIPLIER)

    def test_terms_inside_urls_merge_tags_and_html_attributes_are_ignored(self):
        body = '<p>See <a href="https://example.com/free-trial?offer=act-now">the guide</a> for {{free_gift_code}}.</p>'
        self.assertEqual(terms(run("Hi", body, compliance_checks=False)), [])

    def test_regex_terms(self):
        self.assertIn("income claim ($ per day/week/month)", terms(run("Hi", "Make $500 per day from home.")))
        self.assertIn("percentage-off discount", terms(run("Hi", "Get 30% off this week.")))
        self.assertIn("big money figure", terms(run("Hi", "We saved them $2,500,000 last year.")))

    def test_spam_self_disclaimer_is_high_severity(self):
        finding = next(f for f in run("Hi", "This is not spam, promise.").findings if f.term == "this is not spam")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.points, 10)

    def test_ignore_specific_term_and_rule(self):
        term_id = next(t.id for t in RULES.terms if t.term == "act now")
        report = run("Hi", "Act now!", ignore_rules=[f"SPAM_TERM:{term_id}", "COMPLIANCE_NO_OPT_OUT"])
        self.assertNotIn("act now", terms(report))
        self.assertFalse(has(report, "COMPLIANCE_NO_OPT_OUT"))


class SubjectTests(unittest.TestCase):
    def test_fake_reply_prefix_on_first_touch(self):
        report = run("Re: our chat", CLEAN_BODY)
        self.assertTrue(has(report, "SUBJ_DECEPTIVE_PREFIX"))
        self.assertTrue(has(run("FWD: notes", CLEAN_BODY), "SUBJ_DECEPTIVE_PREFIX"))

    def test_reply_prefix_on_follow_up_is_informational(self):
        report = run("Re: our chat", CLEAN_BODY, step=2)
        self.assertFalse(has(report, "SUBJ_DECEPTIVE_PREFIX"))
        finding = next(f for f in report.findings if f.rule_id == "SUBJ_MANUAL_REPLY_PREFIX")
        self.assertEqual(finding.severity, "info")

    def test_empty_subject_on_first_step(self):
        self.assertTrue(has(run("", CLEAN_BODY, step=1), "SUBJ_EMPTY"))

    def test_all_caps_emoji_length_and_punctuation(self):
        self.assertTrue(has(run("BIG NEWS FOR YOUR TEAM", CLEAN_BODY), "SUBJ_ALL_CAPS"))
        self.assertFalse(has(run("Idea for the CRM team", CLEAN_BODY), "SUBJ_ALL_CAPS"))
        emoji = next(f for f in run("Idea \U0001F680\U0001F525", CLEAN_BODY).findings if f.rule_id == "SUBJ_EMOJI")
        self.assertEqual(emoji.severity, "medium")
        self.assertTrue(has(run("x" * 61, CLEAN_BODY), "SUBJ_TOO_LONG"))
        self.assertTrue(has(run("Big idea!", CLEAN_BODY), "SUBJ_EXCESS_PUNCTUATION"))
        self.assertTrue(has(run("Is this you??", CLEAN_BODY), "SUBJ_EXCESS_PUNCTUATION"))

    def test_link_in_subject(self):
        self.assertTrue(has(run("See https://example.com", CLEAN_BODY), "SUBJ_LINK"))


class MacroTests(unittest.TestCase):
    def test_valid_platform_variables_and_custom_fields(self):
        body = "Hi {{first_name}} at {{company_name}}, re {{industry_vertical}}. If not relevant, let me know and I won't follow up."
        report = run("Hi", body, platform="smartlead", custom_fields=["industry_vertical"])
        self.assertEqual([f for f in rule_ids(report) if f.startswith(("MACRO", "SPINTAX"))], [])

    def test_unclosed_and_unopened_tags(self):
        report = run("Hi", "Hi {{first_name, and first_name}} too.")
        self.assertTrue(has(report, "MACRO_UNCLOSED"))
        self.assertTrue(has(report, "MACRO_UNOPENED"))
        self.assertEqual(report.status, "FAIL", "broken merge tags are blocking")

    def test_unclosed_tag_with_single_closing_brace_is_one_finding(self):
        report = run("Hi", "Hi {{first_name}, welcome.")
        self.assertEqual([r for r in rule_ids(report) if r.startswith(("MACRO", "SPINTAX"))], ["MACRO_UNCLOSED"])

    def test_empty_triple_nested_and_invalid_names(self):
        self.assertTrue(has(run("Hi", "Hi {{}} there"), "MACRO_EMPTY"))
        self.assertTrue(has(run("Hi", "Hi {{{first_name}}} there"), "MACRO_TRIPLE_BRACE"))
        self.assertTrue(has(run("Hi", "Hi {{first-name}} there"), "MACRO_INVALID_NAME"))
        self.assertTrue(has(run("Hi", "Hi {{first name}} there"), "MACRO_INVALID_NAME"))

    def test_single_brace_variable_is_sent_literally(self):
        finding = next(f for f in run("Hi", "Hi {first_name},").findings if f.rule_id == "MACRO_SINGLE_BRACE")
        self.assertEqual(finding.severity, "critical")
        self.assertIn("{{first_name}}", finding.remediation)

    def test_case_and_platform_mismatch_suggests_correct_variable(self):
        smartlead = next(f for f in run("Hi", "Hi {{firstName}}", platform="smartlead").findings if f.rule_id == "MACRO_CASE_MISMATCH")
        self.assertIn("{{first_name}}", smartlead.remediation)
        instantly = next(f for f in run("Hi", "Hi {{first_name}}", platform="instantly").findings if f.rule_id == "MACRO_CASE_MISMATCH")
        self.assertIn("{{firstName}}", instantly.remediation)
        self.assertTrue(has(run("Hi", "Hi {{First_Name}}", platform="smartlead"), "MACRO_CASE_MISMATCH"))

    def test_unsupported_variable_in_strict_profile_only(self):
        self.assertTrue(has(run("Hi", "Hi {{favourite_colour}}", platform="smartlead"), "MACRO_UNSUPPORTED"))
        self.assertFalse(has(run("Hi", "Hi {{favourite_colour}}", platform="generic"), "MACRO_UNSUPPORTED"))

    def test_whitespace_inside_tags_depends_on_profile(self):
        self.assertTrue(has(run("Hi", "Hi {{ first_name }}", platform="smartlead"), "MACRO_WHITESPACE"))
        self.assertFalse(has(run("Hi", "Hi {{ firstName }}", platform="instantly"), "MACRO_WHITESPACE"))

    def test_fallback_syntax_is_flagged_for_verification(self):
        self.assertTrue(has(run("Hi", "Hi {{first_name|there}}", platform="smartlead"), "MACRO_FALLBACK_UNSUPPORTED"))

    def test_brace_spintax(self):
        self.assertEqual([r for r in rule_ids(run("Hi", "{Hi|Hello} {{first_name}}", platform="smartlead")) if "SPINTAX" in r], [])
        self.assertTrue(has(run("Hi", "{Hi||Hello} there", platform="smartlead"), "SPINTAX_EMPTY_OPTION"))
        self.assertTrue(has(run("Hi", "{Hi|Hello} there", platform="instantly"), "SPINTAX_PLATFORM_MISMATCH"))
        self.assertTrue(has(run("Hi", "{Hi|Hello there", platform="smartlead"), "SPINTAX_UNBALANCED"))

    def test_random_spintax(self):
        self.assertEqual([r for r in rule_ids(run("Hi", "{{RANDOM | Hi | Hello}} {{firstName}}", platform="instantly")) if "SPINTAX" in r or "MACRO" in r], [])
        self.assertTrue(has(run("Hi", "{{RANDOM | Hi}}", platform="instantly"), "SPINTAX_SINGLE_OPTION"))
        self.assertTrue(has(run("Hi", "{{RANDOM | Hi | | Hey}}", platform="instantly"), "SPINTAX_EMPTY_OPTION"))
        self.assertTrue(has(run("Hi", "{{RANDOM | Hi | Hello}}", platform="smartlead"), "SPINTAX_PLATFORM_MISMATCH"))

    def test_foreign_merge_syntaxes(self):
        for sample in ("Hi *|FNAME|*,", "Hi %FIRSTNAME%,", "Hi <<First Name>>,", "Hi ${firstName},", "{% if company %}x{% endif %}", "Hi {{ contact.firstname }},"):
            with self.subTest(sample=sample):
                self.assertTrue(has(run("Hi", sample, platform="smartlead"), "MACRO_FOREIGN_SYNTAX"))

    def test_leftover_placeholders(self):
        for sample in ("Hi [First Name],", "Great work at [Company].", "TODO: add proof point", "Lorem ipsum dolor", "Call me on XXX", "Hi <insert name>,"):
            with self.subTest(sample=sample):
                self.assertTrue(has(run("Hi", sample), "PLACEHOLDER_LEFTOVER"))

    def test_macros_in_subject_are_validated(self):
        report = run("Idea for {{company_name", CLEAN_BODY)
        finding = next(f for f in report.findings if f.rule_id == "MACRO_UNCLOSED")
        self.assertEqual(finding.part, "subject")

    def test_css_braces_are_not_macro_errors(self):
        body = "<style>p { color: #333; }</style><p>Hi {{first_name}}, if not relevant let me know and I won't follow up.</p>"
        self.assertEqual([r for r in rule_ids(run("Hi", body)) if r.startswith(("MACRO", "SPINTAX"))], [])


class LinkTests(unittest.TestCase):
    def link_rules(self, body, **opts):
        return [r for r in rule_ids(run("Hi", body, compliance_checks=False, **opts)) if r.startswith("LINK_")]

    def test_shortener_insecure_ip_and_javascript(self):
        self.assertIn("LINK_SHORTENER", self.link_rules("See https://bit.ly/abc"))
        self.assertIn("LINK_INSECURE", self.link_rules("See http://example.com/page"))
        self.assertIn("LINK_IP_HOST", self.link_rules("See https://192.0.2.10/login"))
        self.assertIn("LINK_JAVASCRIPT", self.link_rules('<p><a href="javascript:alert(1)">x</a></p>'))

    def test_malformed_hrefs(self):
        self.assertIn("LINK_MISSING_SCHEME", self.link_rules('<p><a href="www.example.com">site</a></p>'))
        self.assertIn("LINK_EMPTY_HREF", self.link_rules('<p><a href="">site</a></p>'))
        self.assertIn("LINK_EMPTY_HREF", self.link_rules('<p><a href="#">site</a></p>'))
        self.assertIn("LINK_EMPTY_HREF", self.link_rules("<p><a>site</a></p>"))
        self.assertIn("LINK_DOUBLE_SCHEME", self.link_rules('<p><a href="https://https://example.com">site</a></p>'))
        self.assertIn("LINK_MALFORMED", self.link_rules('<p><a href="https://example .com/x">site</a></p>'))
        self.assertIn("LINK_MALFORMED", self.link_rules('<p><a href="https://example.com>site</a></p>'))
        self.assertIn("LINK_MALFORMED", self.link_rules('<p><a href="https://exa_mple">site</a></p>'))

    def test_anchor_text_mismatch_and_match(self):
        self.assertIn("LINK_TEXT_MISMATCH", self.link_rules('<p><a href="https://other.example/x">www.example.com</a></p>'))
        self.assertNotIn("LINK_TEXT_MISMATCH", self.link_rules('<p><a href="https://www.example.com/pricing">example.com</a></p>'))

    def test_unclosed_anchor(self):
        self.assertIn("LINK_UNCLOSED_ANCHOR", self.link_rules('<p><a href="https://example.com">site</p>'))

    def test_link_count_and_first_email_link(self):
        body = " ".join(f"https://example.com/p{i}" for i in range(4))
        self.assertIn("LINK_COUNT", self.link_rules(body))
        self.assertIn("LINK_IN_FIRST_EMAIL", self.link_rules("See https://example.com"))
        self.assertNotIn("LINK_IN_FIRST_EMAIL", [r for r in rule_ids(run("", "See https://example.com", step=2)) if r.startswith("LINK_")])

    def test_mailto_trailing_punctuation_and_macro_urls(self):
        self.assertEqual(self.link_rules('<p><a href="mailto:team@example.com">email</a></p>', ), [])
        self.assertEqual(self.link_rules("Details at https://example.com/page.", ), ["LINK_IN_FIRST_EMAIL"])
        self.assertEqual(self.link_rules("Your page: https://{{website}}/pricing", platform="smartlead"), ["LINK_IN_FIRST_EMAIL"])


class PixelAndImageTests(unittest.TestCase):
    def rules_for(self, body):
        return rule_ids(run("Hi", "<p>Hello there, if not relevant let me know and I won't follow up.</p>" + body))

    def test_valid_pixel_only_reports_manual_tracking(self):
        found = [r for r in self.rules_for('<img src="https://track.example.com/o.gif?id={{email}}" width="1" height="1" alt="">') if r.startswith(("PIXEL", "IMG", "MACRO"))]
        self.assertEqual(found, ["PIXEL_MANUAL_TRACKING"])

    def test_pixel_syntax_errors(self):
        cases = {
            '<img width="1" height="1">': "PIXEL_NO_SRC",
            '<img src="" width="1" height="1">': "PIXEL_NO_SRC",
            '<img src="http://track.example.com/o.gif" width="1" height="1">': "PIXEL_INSECURE",
            '<img src="//track.example.com/o.gif" width="1" height="1">': "PIXEL_PROTOCOL_RELATIVE",
            '<img src="/o.gif" width="1" height="1">': "PIXEL_INVALID_SRC",
            '<img src="https://track.example.com/o.gif width="1" height="1">': "PIXEL_MALFORMED_TAG",
            '<img src="https://track.example.com/o.gif" width="1" height="1"': "PIXEL_MALFORMED_TAG",
            '<img src="https://track.example.com/o.gif?id={{email}" width="1" height="1">': "PIXEL_MACRO_ERROR",
            '<img src="https://track.example.com/o.gif" width="1" height="1" style="display:none">': "PIXEL_HIDDEN_STYLE",
        }
        for tag, expected in cases.items():
            with self.subTest(tag=tag):
                self.assertIn(expected, self.rules_for(tag))

    def test_duplicate_pixels(self):
        tag = '<img src="https://track.example.com/o.gif" width="1" height="1" alt="">'
        self.assertIn("PIXEL_DUPLICATE", self.rules_for(tag + tag))

    def test_regular_images(self):
        found = self.rules_for('<img src="https://cdn.example.com/banner.png" width="600">')
        self.assertIn("IMG_IN_COLD_EMAIL", found)
        self.assertIn("IMG_NO_ALT", found)
        self.assertIn("IMG_BASE64", self.rules_for('<img src="data:image/png;base64,AAAA" alt="x">'))


class HtmlTests(unittest.TestCase):
    def html_rules(self, body):
        return [r for r in rule_ids(run("Hi", body, compliance_checks=False)) if r.startswith("HTML_")]

    def test_balanced_html_is_clean(self):
        self.assertEqual(self.html_rules("<div><p>Hi <b>there</b>,</p><p>Short note.</p></div>"), [])

    def test_forbidden_tags(self):
        for tag in ("<script>alert(1)</script>", "<iframe src='https://example.com'></iframe>", "<form action='https://example.com'></form>"):
            with self.subTest(tag=tag):
                self.assertIn("HTML_FORBIDDEN_TAG", self.html_rules("<p>Hi</p>" + tag))

    def test_hidden_text(self):
        for style in ("display:none", "font-size:0", "color:#ffffff", "visibility: hidden"):
            with self.subTest(style=style):
                self.assertIn("HTML_HIDDEN_TEXT", self.html_rules(f'<p>Hi</p><span style="{style}">hidden words</span>'))

    def test_unclosed_stray_and_malformed_tags(self):
        self.assertIn("HTML_UNCLOSED_TAG", self.html_rules("<p>Hi <b>there</p>"))
        self.assertIn("HTML_STRAY_CLOSING_TAG", self.html_rules("<p>Hi there</strong></p>"))
        self.assertIn("HTML_MALFORMED_TAG", self.html_rules('<p>Hi <span class="x" there</p>'))


class FormattingTests(unittest.TestCase):
    def test_caps_ratio_and_words_respect_acronyms(self):
        shouty = "THIS IS A VERY LOUD EMAIL ABOUT YOUR TEAM AND YOUR PIPELINE GOALS FOR NEXT QUARTER."
        self.assertTrue(has(run("Hi", shouty), "CAPS_RATIO"))
        self.assertTrue(has(run("Hi", "This is HUGE news."), "CAPS_WORD"))
        self.assertFalse(has(run("Hi", "Our CRM, HTML and GDPR work for the CISO team."), "CAPS_WORD"))

    def test_punctuation(self):
        self.assertTrue(has(run("Hi", "Really?!? Yes."), "PUNCT_REPEATED"))
        self.assertTrue(has(run("Hi", "Great! Thanks! Bye!"), "PUNCT_EXCLAMATION_COUNT"))
        self.assertFalse(has(run("Hi", "Great, thanks."), "PUNCT_EXCLAMATION_COUNT"))
        self.assertTrue(has(run("Hi", "Prices ***** below"), "PUNCT_SYMBOL_RUN"))

    def test_hidden_characters_and_homoglyphs(self):
        self.assertTrue(has(run("Hi", "Fr​ee offer"), "ENCODING_HIDDEN_CHAR"))
        self.assertTrue(has(run("Hi", "Log in to pаypal today"), "ENCODING_HOMOGLYPH"))
        self.assertFalse(has(run("Hi", "Café meeting in München"), "ENCODING_HOMOGLYPH"))

    def test_length(self):
        self.assertTrue(has(run("Hi", "word " * 250), "LENGTH_TOO_LONG"))
        self.assertEqual(next(f for f in run("Hi", "Short note here.").findings if f.rule_id == "LENGTH_TOO_SHORT").severity, "info")
        self.assertTrue(has(run("Hi", ""), "BODY_EMPTY"))


class ComplianceTests(unittest.TestCase):
    def test_opt_out_detection(self):
        self.assertTrue(has(run("Hi", "Hello there, worth a chat?"), "COMPLIANCE_NO_OPT_OUT"))
        for line in ("Reply 'stop' to opt out.", "Unsubscribe: {{unsubscribe_link}}", "If it's not a fit, let me know and I won't follow up."):
            with self.subTest(line=line):
                self.assertFalse(has(run("Hi", "Hello there. " + line), "COMPLIANCE_NO_OPT_OUT"))

    def test_can_be_disabled(self):
        self.assertFalse(has(run("Hi", "Hello there", compliance_checks=False), "COMPLIANCE_NO_OPT_OUT"))


class ScoringTests(unittest.TestCase):
    def test_score_curve_and_bands(self):
        self.assertEqual(A.score_from_points(0), 0)
        self.assertEqual(A.score_from_points(10), 25)
        self.assertEqual(A.score_from_points(35), 63)
        self.assertEqual(A.score_from_points(10_000), 100)
        self.assertEqual([A.band_for(s) for s in (0, 19, 20, 40, 60, 80, 100)], ["LOW", "LOW", "MODERATE", "ELEVATED", "HIGH", "CRITICAL", "CRITICAL"])

    def test_score_is_monotonic_with_more_spam(self):
        mild = run("Hi", "Free consultation available.", compliance_checks=False).score
        heavy = run("URGENT!!!", "ACT NOW! 100% free, guaranteed, risk-free. This is not spam. Click here!", compliance_checks=False).score
        self.assertLess(mild, heavy)
        self.assertGreaterEqual(heavy, 80)

    def test_status_thresholds(self):
        self.assertEqual(run("Hi", "Hello there, worth a chat?", compliance_checks=False).status, "PASS")
        self.assertEqual(run("Hi", "Act now, worth a chat?", compliance_checks=False).status, "WARN")
        spammy = "ACT NOW! 100% free, guaranteed, risk-free. This is not spam."
        self.assertEqual(run("Hi", spammy, compliance_checks=False).status, "FAIL")
        self.assertEqual(run("Hi", spammy, compliance_checks=False, fail_threshold=101).status, "WARN")
        self.assertEqual(run("Hi", "Hi {{first_name", fail_on_severity="none", compliance_checks=False).status, "WARN")

    def test_invalid_options(self):
        with self.assertRaises(A.InputError):
            A.Analyzer(RULES, A.AnalyzerOptions(platform="unknown-engine"))
        with self.assertRaises(A.InputError):
            A.Analyzer(RULES, A.AnalyzerOptions(fail_on_severity="severe"))

    def test_findings_are_sorted_subject_first(self):
        report = run("Urgent", "Act now please.")
        self.assertEqual(report.findings[0].part, "subject")


class InputLoadingTests(unittest.TestCase):
    def write(self, name, content, mode="w"):
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, name)
        with open(path, mode) as handle:
            handle.write(content)
        self.addCleanup(lambda: (os.unlink(path), os.rmdir(directory)))
        return path

    def test_json_shapes(self):
        shapes = [
            [{"subject": "A", "body": "one"}, {"subject": "", "body": "two"}],
            {"steps": [{"subject": "A", "body": "one"}, {"subject": "", "body": "two"}]},
            {"sequences": [{"name": "Seq", "steps": [{"step": 1, "subject": "A", "email_body": "one"}, {"step": 2, "html": "two"}]}]},
        ]
        for shape in shapes:
            with self.subTest(shape=shape):
                emails = A.load_file(self.write("seq.json", json.dumps(shape)))
                self.assertEqual([(e.step, e.body) for e in emails], [(1, "one"), (2, "two")])

    def test_ab_variants(self):
        data = {"steps": [{"step": 1, "subject": "Shared", "variants": [{"body": "a"}, {"subject": "Own", "body": "b"}]}]}
        emails = A.load_file(self.write("ab.json", json.dumps(data)))
        self.assertEqual([(e.subject, e.label) for e in emails], [("Shared", "step 1 variant A"), ("Own", "step 1 variant B")])

    def test_csv_text_and_eml(self):
        csv_emails = A.load_file(self.write("s.csv", "Step,Subject,Body\n1,Hello,First body\n2,,Second body\n"))
        self.assertEqual([(e.step, e.subject, e.body) for e in csv_emails], [(1, "Hello", "First body"), (2, "", "Second body")])
        text = A.load_file(self.write("s.txt", "Subject: Quick idea\n\nHi {{first_name}},\nBody here."))[0]
        self.assertEqual((text.subject, text.body), ("Quick idea", "Hi {{first_name}},\nBody here."))
        plain = A.load_file(self.write("b.html", "<p>No subject</p>"))[0]
        self.assertEqual((plain.subject, plain.body), ("", "<p>No subject</p>"))
        eml = "Subject: Hello there\nContent-Type: text/plain; charset=utf-8\n\nBody of the message.\n"
        message = A.load_file(self.write("m.eml", eml))[0]
        self.assertEqual((message.subject, message.body.strip()), ("Hello there", "Body of the message."))

    def test_input_errors(self):
        with self.assertRaises(A.InputError):
            A.load_file(os.path.join(ROOT, "missing.json"))
        with self.assertRaises(A.InputError):
            A.load_file(self.write("bad.json", "{oops"))
        with self.assertRaises(A.InputError):
            A.load_file(self.write("none.json", json.dumps({"unrelated": True})))
        with self.assertRaises(A.InputError):
            A.load_file(self.write("bad.csv", "subject,notes\nHi,x\n"))


class CliTests(unittest.TestCase):
    def cli(self, *argv):
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stderr(err):
            code = A.main(list(argv), stdout=out)
        return code, out.getvalue(), err.getvalue()

    def test_json_report_structure_and_exit_codes(self):
        code, out, _ = self.cli("--subject", CLEAN_SUBJECT, "--body", CLEAN_BODY, "--platform", "smartlead", "--format", "json", "--no-timestamp")
        self.assertEqual(code, A.EXIT_PASS)
        report = json.loads(out)
        self.assertEqual(report["tool"], A.TOOL_NAME)
        self.assertNotIn("generated_at", report)
        self.assertEqual(report["summary"]["status"], "PASS")
        self.assertEqual(report["results"][0]["findings"], [])

        code, out, _ = self.cli("--subject", "Re: URGENT", "--body", "Hi {{first_name, act now!!!", "--format", "json")
        self.assertEqual(code, A.EXIT_FAIL)
        report = json.loads(out)
        self.assertIn("generated_at", report)
        finding = report["results"][0]["findings"][0]
        for key in ("rule_id", "severity", "part", "line", "column", "message", "remediation", "excerpt", "points"):
            self.assertIn(key, finding)

    def test_text_report_and_file_inputs(self):
        sample = os.path.join(ROOT, "examples", "sample_sequence.json")
        code, out, _ = self.cli(sample, "--platform", "smartlead", "--custom-fields", "sender_name,lead_id", "--no-color")
        self.assertEqual(code, A.EXIT_FAIL)
        self.assertIn("Spam Risk Score", out)
        self.assertIn("↳ fix:", out)
        self.assertIn("Overall status: FAIL", out)
        self.assertNotIn("\033[", out, "no ANSI codes when not a TTY")

    def test_min_severity_filter_and_output_file(self):
        directory = tempfile.mkdtemp()
        target = os.path.join(directory, "report.json")
        self.addCleanup(lambda: (os.path.exists(target) and os.unlink(target), os.rmdir(directory)))
        code, out, _ = self.cli("--subject", "Hi", "--body", "Hello there", "--format", "json", "--output", target)
        self.assertEqual(code, A.EXIT_PASS)
        self.assertIn("Report written", out)
        with open(target, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["summary"]["emails"], 1)
        _, text, _ = self.cli("--subject", "Hi", "--body", "Hello there", "--min-severity", "high")
        self.assertIn("No findings at or above 'high'", text)

    def test_usage_errors_exit_2(self):
        self.assertEqual(self.cli()[0], A.EXIT_USAGE)
        self.assertEqual(self.cli("--subject", "x", "--body", "y", "--platform", "nope")[0], A.EXIT_USAGE)
        self.assertEqual(self.cli("does-not-exist.json")[0], A.EXIT_USAGE)
        self.assertEqual(self.cli("--rules", "missing-rules.json", "--body", "x")[0], A.EXIT_USAGE)

    def test_stdin_and_list_rules(self):
        with mock.patch.object(sys, "stdin", io.StringIO("Subject: Hello\n\nAct now!")):
            code, out, _ = self.cli("-", "--format", "json", "--no-timestamp")
        report = json.loads(out)
        self.assertEqual(report["results"][0]["source"], "<stdin>")
        self.assertIn("act now", [f.get("term") for f in report["results"][0]["findings"]])
        code, out, _ = self.cli("--list-rules")
        self.assertEqual(code, A.EXIT_PASS)
        self.assertGreaterEqual(len(out.strip().splitlines()), 150)


class RobustnessTests(unittest.TestCase):
    def test_large_input_is_fast(self):
        body = ("Hi {{first_name}}, here is a normal sentence about CRM hygiene and pipeline reviews. " * 600) + " Act now."
        start = time.perf_counter()
        report = run("Hi", body)
        self.assertLess(time.perf_counter() - start, 5.0)
        self.assertIn("act now", terms(report))

    def test_weird_input_never_crashes(self):
        samples = ["", "{", "}", "{{", "}}", "<", ">", "<a", "<img", "{{}}{{", "\x00\x01", "😀" * 50, "<a href='x'>" * 30, "{" * 500]
        for sample in samples:
            with self.subTest(sample=sample[:20]):
                report = run(sample, sample)
                self.assertTrue(0 <= report.score <= 100)

    def test_windows_line_endings_keep_line_numbers(self):
        report = run("Hi", "Line one\r\nLine two act now")
        finding = next(f for f in report.findings if f.term == "act now")
        self.assertEqual((finding.line, finding.column), (2, 10))


class RepositoryHygieneTests(unittest.TestCase):
    """Guard against committing secrets or real addresses (client-safe repository)."""

    def test_no_secrets_or_real_email_addresses(self):
        forbidden = [
            re.compile(r"sk-[A-Za-z0-9]{20,}"),
            re.compile(r"xox[abposr]-\d{6,}"),
            re.compile(r"AKIA[0-9A-Z]{16}"),
            re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            re.compile(r"pat-(?:na|eu|ap)\d-[0-9a-f]{8}-"),
        ]
        allowed_email = re.compile(r"@(?:[a-z0-9-]+\.)*(?:example\.(?:com|org|net)|[a-z0-9-]+\.example)$", re.I)
        for directory, _, files in os.walk(ROOT):
            if any(part in directory for part in (".git", "__pycache__", ".pytest_cache")):
                continue
            for name in files:
                if not name.endswith((".py", ".json", ".md", ".yml", ".txt")) and name != "LICENSE":
                    continue
                path = os.path.join(directory, name)
                if os.path.abspath(path) == os.path.abspath(__file__):
                    continue
                with open(path, encoding="utf-8") as handle:
                    text = handle.read()
                for pattern in forbidden:
                    self.assertIsNone(pattern.search(text), f"{pattern.pattern} found in {path}")
                for address in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
                    self.assertRegex(address, allowed_email, f"non-placeholder email {address} in {path}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
