import importlib.util
import sys
import types
import unittest
from pathlib import Path


def load_main_module():
    module_name = "threatlens_main_under_test"
    if module_name in sys.modules:
        return sys.modules[module_name]

    anthropic = types.ModuleType("anthropic")

    class Anthropic:
        def __init__(self, *args, **kwargs):
            pass

    anthropic.Anthropic = Anthropic

    httpx = types.ModuleType("httpx")

    class URL:
        def __init__(self, value):
            from urllib.parse import urlparse

            parsed = urlparse(value)
            self.host = parsed.hostname
            self._value = value

        def __str__(self):
            return self._value

    class AsyncClient:
        pass

    class TimeoutException(Exception):
        pass

    httpx.URL = URL
    httpx.AsyncClient = AsyncClient
    httpx.TimeoutException = TimeoutException

    whois = types.ModuleType("whois")
    whois.whois = lambda domain: None

    fastapi = types.ModuleType("fastapi")

    class HTTPException(Exception):
        def __init__(self, status_code, detail):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class FastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def add_middleware(self, *args, **kwargs):
            return None

        def get(self, *args, **kwargs):
            def decorator(fn):
                return fn

            return decorator

        def post(self, *args, **kwargs):
            def decorator(fn):
                return fn

            return decorator

    fastapi.FastAPI = FastAPI
    fastapi.HTTPException = HTTPException

    cors_module = types.ModuleType("fastapi.middleware.cors")
    cors_module.CORSMiddleware = object

    pydantic = types.ModuleType("pydantic")

    class BaseModel:
        def __init__(self, **kwargs):
            fields = {}
            for cls in reversed(self.__class__.mro()):
                fields.update(getattr(cls, "__annotations__", {}))

            for name in fields:
                if name in kwargs:
                    value = kwargs[name]
                elif hasattr(self.__class__, name):
                    value = getattr(self.__class__, name)
                else:
                    raise TypeError(f"Missing field: {name}")
                setattr(self, name, value)

    pydantic.BaseModel = BaseModel

    sys.modules["anthropic"] = anthropic
    sys.modules["httpx"] = httpx
    sys.modules["whois"] = whois
    sys.modules["fastapi"] = fastapi
    sys.modules["fastapi.middleware"] = types.ModuleType("fastapi.middleware")
    sys.modules["fastapi.middleware.cors"] = cors_module
    sys.modules["pydantic"] = pydantic

    path = Path(__file__).with_name("main.py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class ThreatLensRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = load_main_module()

    def test_sanitize_keeps_generic_dates_and_ids(self):
        text = (
            "Spotify receipt generated on 04/12/2026. "
            "Reference AB12345678 is attached. "
            "Visit https://spotify.com/account for details."
        )

        sanitized = self.main.sanitize_for_ai(text)

        self.assertIn("04/12/2026", sanitized)
        self.assertIn("AB12345678", sanitized)
        self.assertIn("https://spotify.com/account", sanitized)

    def test_sanitize_redacts_contextual_pii(self):
        text = (
            "DOB: 04/12/2026\n"
            "Passport Number: AB1234567\n"
            "IBAN: GB82 WEST 1234 5698 7654 32\n"
            "Card: 4111 1111 1111 1111\n"
            "Password: hunter2"
        )

        sanitized = self.main.sanitize_for_ai(text)

        self.assertIn("[DATE_OF_BIRTH]", sanitized)
        self.assertIn("[PASSPORT]", sanitized)
        self.assertIn("[IBAN]", sanitized)
        self.assertIn("[CARD_NUMBER]", sanitized)
        self.assertIn("Password: [REDACTED]", sanitized)

    def test_trusted_domain_single_engine_vt_hit_is_not_escalated(self):
        is_malicious, is_suspicious = self.main.classify_vt_scan(
            "https://play.google.com/store/apps/details?id=com.spotify.music",
            malicious=1,
            suspicious=0,
            harmless=15,
        )

        self.assertFalse(is_malicious)
        self.assertFalse(is_suspicious)

    def test_calibration_blocks_unsupported_malicious_verdict(self):
        payload = self.main.EmailPayload(
            sender=self.main.Sender(name="Google", email="alerts@google.com"),
            subject="Security alert",
            body="We noticed a new sign-in to your account.",
            links=["https://accounts.google.com/"],
            linkCount=1,
            wordCount=9,
        )

        analysis = {
            "threat_level": "MALICIOUS",
            "confidence": 0.93,
            "summary": "Potential credential theft.",
            "key_findings": ["Urgent security wording"],
            "recommended_action": "Do not click anything.",
        }

        scans = [
            self.main.LinkScan(
                url="https://accounts.google.com/",
                harmless=12,
                total=12,
                status="ok",
            )
        ]
        whois_list = [
            self.main.WhoisInfo(
                domain="google.com",
                registrar="MarkMonitor",
                country="US",
                age_days=5000,
                is_new=False,
            )
        ]
        dns_list = [
            self.main.DnsInfo(
                domain="google.com",
                has_spf=True,
                has_dmarc=True,
                mx_records=["aspmx.l.google.com"],
            )
        ]

        calibrated = self.main.calibrate_ai_analysis(
            payload,
            analysis,
            scans,
            whois_list,
            dns_list,
            [],
            [],
            [],
            self.main.MalwareBazaarResult(),
        )

        self.assertEqual(calibrated["threat_level"], "SAFE")
        self.assertGreaterEqual(calibrated["confidence"], 0.75)

    def test_spotify_subdomain_with_inherited_auth_stays_safe(self):
        payload = self.main.EmailPayload(
            sender=self.main.Sender(name="Spotify", email="no-reply@legal.spotify.com"),
            subject="Update your payment details",
            body="Please update your payment details in your Spotify account.",
            links=[
                "https://www.spotify.com/account",
                "https://play.google.com/store/apps/details?id=com.spotify.music",
            ],
            linkCount=2,
            wordCount=10,
        )

        analysis = {
            "threat_level": "SUSPICIOUS",
            "confidence": 0.72,
            "summary": "This may be risky.",
            "key_findings": ["Urgency wording", "One link was flagged"],
            "recommended_action": "Avoid clicking the links.",
        }

        scans = [
            self.main.LinkScan(
                url="https://www.spotify.com/account",
                harmless=20,
                total=20,
                status="ok",
            ),
            self.main.LinkScan(
                url="https://play.google.com/store/apps/details?id=com.spotify.music",
                malicious=1,
                harmless=15,
                total=16,
                status="ok",
                is_suspicious=False,
            ),
        ]
        whois_list = [
            self.main.WhoisInfo(
                domain="legal.spotify.com",
                registrar="MarkMonitor",
                country="SE",
                age_days=2500,
                is_new=False,
            )
        ]
        dns_list = [
            self.main.DnsInfo(
                domain="legal.spotify.com",
                auth_domain="spotify.com",
                has_spf=True,
                has_dmarc=True,
                mx_records=["mx.spotify.com"],
            )
        ]

        calibrated = self.main.calibrate_ai_analysis(
            payload,
            analysis,
            scans,
            whois_list,
            dns_list,
            [],
            [],
            [],
            self.main.MalwareBazaarResult(),
        )

        self.assertEqual(calibrated["threat_level"], "SAFE")
        self.assertGreaterEqual(calibrated["confidence"], 0.75)


if __name__ == "__main__":
    unittest.main()
