"""Tests for phishing_detector. Run: python -m unittest discover -s tests -v"""
import unittest

from phishing_detector.detector import analyse, risk_level


class TestScoring(unittest.TestCase):
    def test_benign_url_is_low(self):
        result = analyse("See https://example.com/about for details.")
        self.assertEqual(result.level, "Low")
        self.assertLess(result.score, 30)

    def test_ip_literal_scores_high(self):
        result = analyse("Login here: http://192.168.1.100/login")
        self.assertTrue(any("IP-literal" in r for r in result.reasons))
        self.assertGreaterEqual(result.score, 30)

    def test_url_shortener_flagged(self):
        result = analyse("Check this: https://bit.ly/abc123")
        self.assertTrue(any("shortener" in r for r in result.reasons))

    def test_display_mismatch_flagged(self):
        text = '[paypal.com](https://evil-example.com/login)'
        result = analyse(text)
        self.assertTrue(any("mismatch" in r for r in result.reasons))
        self.assertGreaterEqual(result.score, 30)

    def test_html_display_mismatch_flagged(self):
        text = '<a href="https://evil-example.com/login">paypal.com</a>'
        result = analyse(text)
        self.assertTrue(any("mismatch" in r for r in result.reasons))

    def test_urgency_and_attachment_raise_score(self):
        text = ("URGENT: your account is suspended, act now! "
                "See attached invoice.exe for details.")
        result = analyse(text)
        self.assertTrue(any("Urgency" in r for r in result.reasons))
        self.assertTrue(any("attachment" in r for r in result.reasons))
        self.assertGreater(result.score, 0)

    def test_punycode_flagged(self):
        result = analyse("Visit https://xn--pypal-4ve.com/login")
        self.assertTrue(any("Punycode" in r for r in result.reasons))

    def test_excessive_subdomains_flagged(self):
        result = analyse("https://a.b.c.d.example.com/login")
        self.assertTrue(any("subdomains" in r for r in result.reasons))

    def test_score_is_capped_at_100(self):
        text = ("URGENT account suspended act now immediately! "
                "http://10.0.0.1/login https://bit.ly/x "
                "attachment: invoice.exe and payload.scr "
                "https://xn--pypal-4ve.com/ https://a.b.c.d.evil-example.com/")
        result = analyse(text)
        self.assertLessEqual(result.score, 100)
        self.assertEqual(result.level, "High")

    def test_risk_level_boundaries(self):
        self.assertEqual(risk_level(0), "Low")
        self.assertEqual(risk_level(29), "Low")
        self.assertEqual(risk_level(30), "Medium")
        self.assertEqual(risk_level(64), "Medium")
        self.assertEqual(risk_level(65), "High")
        self.assertEqual(risk_level(100), "High")

    def test_empty_input_is_low_with_no_signal_note(self):
        result = analyse("Hello, just checking in.")
        self.assertEqual(result.level, "Low")
        self.assertEqual(result.score, 0)

    def test_non_string_raises(self):
        with self.assertRaises(TypeError):
            analyse(None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
