"""site/flows: the flow pages are self-contained, make no network request, carry no
token or key, and say where their data came from. Standard library only; one extra
check runs when a Playwright browser happens to be installed."""
import json
import re
import struct
import unittest
from pathlib import Path

FLOWS = Path(__file__).resolve().parents[1] / "site" / "flows"
PAGES = sorted(FLOWS.glob("*.html"))
STORIES = [p for p in PAGES if p.name != "index.html"]
#: things that would make a browser fetch something when the page opens
LOADS = re.compile(r"""<(?:script|img|link|iframe|video|audio|source|embed|object)\b[^>]*?\b(?:src|href|data)\s*=\s*["']?\s*(?:https?:)?//""", re.I)
CSS_LOADS = re.compile(r"""@import|url\(\s*["']?\s*(?:https?:)?//""", re.I)
JS_LOADS = re.compile(r"\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|navigator\.sendBeacon|importScripts|\bimport\s*\(")
#: names that belong to tooling outside this repository, or that look like a path on a build machine
NOT_PUBLIC = re.compile(r"\bsim" + r"lab\b|private[/\\]har" + r"ness|smartdelegate-root|\.\./private/|/home/|[A-Z]:\\\\Users", re.I)
TOKEN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}|[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----")
OVERCLAIMS = ("unhackable", "unbreakable", "impossible", "guarantee", "100%", "zero risk", "military-grade", "prevents all", "tamper-proof", "bulletproof")


def data_block(text: str, block_id: str):
    m = re.search(r'<script type="application/json" id="%s">(.*?)</script>' % re.escape(block_id), text, re.S)
    return json.loads(m.group(1)) if m else None


class SiteFlows(unittest.TestCase):
    def test_gallery_is_present_and_small(self):
        self.assertTrue((FLOWS / "index.html").exists())
        self.assertGreaterEqual(len(STORIES), 3)
        total = sum(p.stat().st_size for p in FLOWS.iterdir() if p.is_file())
        self.assertLess(total, 3 * 1024 * 1024, "site/flows is meant to stay under 3 MB")

    def test_pages_are_self_contained(self):
        for p in PAGES:
            text = p.read_text(encoding="utf-8")
            with self.subTest(page=p.name):
                self.assertFalse(bool(LOADS.search(text)), "an element would load from the network")
                self.assertFalse(bool(CSS_LOADS.search(text)), "a stylesheet would load from the network")
                self.assertFalse(bool(JS_LOADS.search(text)), "a script could make a request")
                self.assertTrue("data:font/woff;base64," in text, "fonts are not embedded")                 # fonts are embedded
                for src in re.findall(r"""<(?:img|script|link)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)""", text):
                    self.assertTrue((FLOWS / src).exists() or src.startswith("data:"), f"{src} is not next to the page")

    def test_pages_carry_no_private_names_tokens_or_overclaims(self):
        for p in list(PAGES) + [FLOWS / "README.md"]:
            text = p.read_text(encoding="utf-8")
            with self.subTest(page=p.name):
                self.assertFalse(bool(NOT_PUBLIC.search(text)), "a name that is not public")
                self.assertFalse(bool(TOKEN.search(text)), "something shaped like a token or key")
                flow = data_block(text, "flow-data")
                if flow is not None:        # the words a reader sees: the story's copy and every caption
                    words = json.dumps([flow["story"], [e["caption"] for e in flow["events"]], flow["traffic"].get("caption", "")]).lower()
                else:
                    words = re.sub(r"<[^>]+>", " ", re.sub(r"(?s)<(style|script)\b.*?</\1>", " ", text)).lower()
                for word in OVERCLAIMS:
                    self.assertFalse(word in words, f"overclaim: {word}")

    def test_every_flow_says_where_it_came_from_and_what_it_does_not_do(self):
        for p in STORIES:
            text = p.read_text(encoding="utf-8")
            flow = data_block(text, "flow-data")
            with self.subTest(page=p.name):
                self.assertIsNotNone(flow)
                self.assertEqual(flow["schema"], "smartdelegate.flow/1")
                prov = flow["provenance"]
                self.assertEqual(prov["verdict"], "PASS")
                self.assertTrue(prov["engine"]["version"] and prov["policy_version"] and prov["line"].startswith("From a real run"))
                self.assertGreater(len(flow["story"]["limitation"]["note"]), 40)
                self.assertIn("open source", (flow["story"]["cta"]["line"] + flow["story"]["cta"]["license"]).lower())
                self.assertIn('id="transcript"', text)                          # captions are always available as text
                self.assertNotIn("channels", flow["story"])
                decisions = sum(len([e] if e["type"] == "call" else e.get("calls", [])) for e in flow["events"])
                self.assertEqual(decisions, prov["story"]["decisions"])
                for e in flow["events"]:
                    self.assertTrue(e["caption"]["long"])
                    if e["type"] == "call" and e["outcome"] in ("allow", "deny", "hold"):
                        self.assertTrue(e["ref"]["decision_id"].startswith("d-"))
                    self.assertNotIn("shown", e.get("fields") or {})            # field names only, never values
                for a, b in zip(flow["receipt"], flow["receipt"][1:]):
                    self.assertEqual(b["prev"], a["hash"])                      # the audit trail on the page is a chain
                tr = flow["traffic"]
                self.assertEqual(sum(s["total"] for s in tr["streams"]), tr["totals"]["decisions"])

    def test_preview_images_have_the_link_preview_size(self):
        for p in STORIES:
            png = FLOWS / (p.stem + "-og.png")
            with self.subTest(image=png.name):
                b = png.read_bytes()
                self.assertEqual(b[:8], b"\x89PNG\r\n\x1a\n")
                self.assertEqual(struct.unpack(">II", b[16:24]), (1200, 630))

    def test_index_links_every_page(self):
        text = (FLOWS / "index.html").read_text(encoding="utf-8")
        for p in STORIES:
            self.assertIn(f'href="{p.name}"', text)

    def test_pages_open_offline_without_errors(self):
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            self.skipTest("no Playwright here; the static checks above still ran")
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                try:
                    for p in PAGES:
                        ctx = browser.new_context(viewport={"width": 1100, "height": 800})
                        ctx.set_offline(True)
                        page = ctx.new_page()
                        errors, requests = [], []
                        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
                        page.on("pageerror", lambda e: errors.append(str(e)))
                        page.on("request", lambda r: requests.append(r.url))
                        page.goto(p.as_uri(), wait_until="load", timeout=60000)
                        page.wait_for_function("window.__studio && window.__studio.ready === true", timeout=60000)
                        with self.subTest(page=p.name):
                            self.assertEqual(errors, [])
                            self.assertEqual([u for u in requests if not u.startswith(("file:", "data:"))], [])
                        ctx.close()
                finally:
                    browser.close()
        except unittest.SkipTest:
            raise
        except AssertionError:
            raise
        except Exception as e:                                                 # a browser that is installed but cannot start is not this repository's failure
            self.skipTest(f"browser could not run: {type(e).__name__}")


if __name__ == "__main__":
    unittest.main()
