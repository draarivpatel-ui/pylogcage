from __future__ import annotations

import base64
import unittest
import urllib.parse

from pylogcage import redact_secrets, sanitize_log_line
from pylogcage.errors import LogCageError

from helpers import PylogcageTestCase, shaped_jwt, synthetic_vendor_secrets

R = "[REDACTED]"


def _positive_test(input_text, expected):
    def test(self):
        self.assertEqual(redact_secrets(input_text), expected)
    return test


def _negative_test(input_text):
    def test(self):
        self.assertEqual(redact_secrets(input_text), input_text)
    return test


class TestRedactSecrets(PylogcageTestCase):
    def test_benign_text_unchanged(self):
        self.assertEqual(redact_secrets("ordinary log message"), "ordinary log message")

    def test_rejects_non_string(self):
        with self.assertRaises(TypeError):
            redact_secrets(None)

    def test_rejects_bad_replacement(self):
        with self.assertRaises(LogCageError):
            redact_secrets("x", replacement="bad\n")

    def test_rejects_scalar_extra_secret(self):
        with self.assertRaises(LogCageError):
            redact_secrets("x", extra_secrets="abc")

    def test_rejects_empty_extra_secret(self):
        with self.assertRaises(LogCageError):
            redact_secrets("x", extra_secrets=[""])

    def test_rejects_too_many_extra_secrets(self):
        with self.assertRaises(LogCageError):
            redact_secrets("x", extra_secrets=["s" + str(i) for i in range(65)])

    def test_custom_replacement(self):
        self.assertEqual(redact_secrets("password=abc", replacement="<hidden>"), "password=<hidden>")

    def test_can_disable_terminal_stripping_for_redactor(self):
        text = "abc\x1b[31mdef"
        self.assertEqual(redact_secrets(text, strip_terminal=False), text)


_AUTH_POSITIVE = [
    ("authorization_bearer", "Authorization: Bearer abcdefgh12345678", "Authorization: Bearer " + R),
    ("lowercase_bearer", "authorization: bearer abcdefgh12345678", "authorization: bearer " + R),
    ("standalone_bearer", "bearer abcdefgh12345678", "bearer " + R),
    ("authorization_basic", "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "Authorization: Basic " + R),
    ("lowercase_basic", "authorization: basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "authorization: basic " + R),
    ("bearer_jwt", "Bearer " + shaped_jwt(), "Bearer " + R),
    ("bearer_punctuation", "Bearer abc-def_123", "Bearer " + R),
    ("multiple_spaces", "Bearer   abcdefgh12345678", "Bearer   " + R),
    ("tab_after_bearer", "Bearer\tabcdefgh12345678", "Bearer\t" + R),
    ("text_after", "Bearer abcdefgh12345678 done", "Bearer " + R + " done"),
    ("auth_alpha_opaque", "Authorization: Bearer abcdefghijklmnop", "Authorization: Bearer " + R),
    ("basic_alpha_opaque", "Authorization: Basic abcdefghijklmnop", "Authorization: Basic " + R),
    ("short_in_authorization", "Authorization: Bearer abc", "Authorization: Bearer " + R),
]
for _name, _input, _expected in _AUTH_POSITIVE:
    setattr(TestRedactSecrets, "test_auth_positive_" + _name, _positive_test(_input, _expected))

_AUTH_NEGATIVE = [
    ("bearer_prose", "bearer of good news"),
    ("basic_prose", "basic authentication"),
    ("bearer_short", "Bearer abc"),
    ("embedded_bearer", "xBearer abcdefgh12345678"),
    ("basic_short", "Basic abc"),
]
for _name, _input in _AUTH_NEGATIVE:
    setattr(TestRedactSecrets, "test_auth_negative_" + _name, _negative_test(_input))


_URL_POSITIVE = [
    ("https_user_pass", "https://user:pass@example.com/path", "https://" + R + "@example.com/path"),
    ("http_user_pass", "http://user:pass@example.com/path", "http://" + R + "@example.com/path"),
    ("uppercase_scheme", "HTTPS://user:pass@example.com/path", "HTTPS://" + R + "@example.com/path"),
    ("user_only", "https://user@example.com/", "https://" + R + "@example.com/"),
    ("multiple_at", "https://a@b@example.com/", "https://" + R + "@example.com/"),
    ("query_after", "https://user:pass@example.com/path?q=1", "https://" + R + "@example.com/path?q=1"),
    ("fragment_after", "https://user:pass@example.com/#x", "https://" + R + "@example.com/#x"),
    ("two_urls", "https://u:p@a.test/ http://x:y@b.test/", "https://" + R + "@a.test/ http://" + R + "@b.test/"),
    ("custom_scheme", "mongodb+srv://u:p@example.test/db", "mongodb+srv://" + R + "@example.test/db"),
    ("postgres_scheme", "postgres://u:p@example.test/db", "postgres://" + R + "@example.test/db"),
]
for _name, _input, _expected in _URL_POSITIVE:
    setattr(TestRedactSecrets, "test_url_positive_" + _name, _positive_test(_input, _expected))

_URL_NEGATIVE = [
    ("without_credentials", "https://example.com/path"),
    ("at_in_path", "https://example.com/user@example.com"),
    ("at_before_scheme", "user@example.com https://example.com/"),
    ("incomplete_scheme", "https:/user:pass@example.com"),
]
for _name, _input in _URL_NEGATIVE:
    setattr(TestRedactSecrets, "test_url_negative_" + _name, _negative_test(_input))


_COOKIE_POSITIVE = [
    ("cookie_end", "Cookie: session=abcdef; theme=light", "Cookie: " + R),
    ("cookie_newline", "Cookie: session=abcdef\nnext", "Cookie: " + R + "\nnext"),
    ("lowercase_cookie", "cookie: session=abcdef", "cookie: " + R),
    ("set_cookie", "Set-Cookie: session=abcdef; Path=/", "Set-Cookie: " + R),
    ("lowercase_set_cookie", "set-cookie: session=abcdef", "set-cookie: " + R),
    ("set_cookie_crlf", "Set-Cookie: session=abcdef\r\nnext", "Set-Cookie: " + R + "\r\nnext"),
    ("cookie_no_space", "Cookie:session=abcdef", "Cookie:" + R),
]
for _name, _input, _expected in _COOKIE_POSITIVE:
    setattr(TestRedactSecrets, "test_cookie_positive_" + _name, _positive_test(_input, _expected))

_COOKIE_NEGATIVE = [
    ("cookie_prose", "cookie jar is open"),
    ("cookied_key", "cookied: abcdef"),
    ("set_cookieless", "set-cookieless: abcdef"),
]
for _name, _input in _COOKIE_NEGATIVE:
    setattr(TestRedactSecrets, "test_cookie_negative_" + _name, _negative_test(_input))


_JWT_POSITIVE = [
    ("bare", shaped_jwt(), R),
    ("sentence", "token " + shaped_jwt() + " end", "token " + R + " end"),
    ("after_equals", "jwt=" + shaped_jwt(), "jwt=" + R),
    ("twice", shaped_jwt() + " " + shaped_jwt(), R + " " + R),
    ("base64url_punctuation", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlXy12", R),
    ("empty_signature", "eyJhbGciOiJub25lIn0.e30.", R),
    ("short_payload", "eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJl", R),
    ("opaque_compact_shape", "eyJaaaaa.bbbbbbbb.cccccccc", R),
]
for _name, _input, _expected in _JWT_POSITIVE:
    setattr(TestRedactSecrets, "test_jwt_positive_" + _name, _positive_test(_input, _expected))

_JWT_NEGATIVE = [
    ("two_part", "abc.def"),
    ("two_part_jwt_shape", "eyJhbGciOiJub25lIn0.e30"),
    ("short_header", "eyJabc.defghijklm.uvwxyz"),
    ("too_short_signature", "eyJhbGciOiJIUzI1NiJ9.e30.abc"),
    ("ordinary_dotted", "aaaaaaaaa.bbbbbbbbb.ccccccccc"),
    ("embedded", "x" + shaped_jwt()),
]
for _name, _input in _JWT_NEGATIVE:
    setattr(TestRedactSecrets, "test_jwt_negative_" + _name, _negative_test(_input))


_PEM_RSA = "-----BEGIN RSA PRIVATE KEY-----\nMIIBsynthetic\n-----END RSA PRIVATE KEY-----"
_PEM_POSITIVE = [
    ("rsa", "x " + _PEM_RSA + " y", "x " + R + " y"),
    ("ec", "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----", R),
    ("openssh", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", R),
    ("unterminated", "x -----BEGIN RSA PRIVATE KEY-----\nabc", "x " + R),
    ("crlf", "-----BEGIN RSA PRIVATE KEY-----\r\nabc\r\n-----END RSA PRIVATE KEY-----\r\nnext", R + "\r\nnext"),
]
for _name, _input, _expected in _PEM_POSITIVE:
    setattr(TestRedactSecrets, "test_pem_positive_" + _name, _positive_test(_input, _expected))

_PEM_NEGATIVE = [
    ("public_key", "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"),
    ("certificate", "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"),
    ("lowercase", "-----begin rsa private key-----\nabc"),
]
for _name, _input in _PEM_NEGATIVE:
    setattr(TestRedactSecrets, "test_pem_negative_" + _name, _negative_test(_input))


def _make_vendor_test(secret):
    def test(self):
        self.assertEqual(redact_secrets("prefix " + secret + " suffix"), "prefix " + R + " suffix")
    return test


for _name, _secret in synthetic_vendor_secrets().items():
    setattr(TestRedactSecrets, "test_vendor_positive_" + _name, _make_vendor_test(_secret))

_VENDOR_FRAGMENTS = [
    ("aws", "AKIAABC"), ("github", "ghp_abc"), ("stripe", "sk_live_abc"),
    ("slack", "xoxb-abc"), ("openai", "sk-abc"), ("anthropic", "sk-ant-abc"),
    ("npm", "npm_abc"), ("pypi", "pypi-abc"), ("google", "AIzaabc"),
]
for _name, _input in _VENDOR_FRAGMENTS:
    setattr(TestRedactSecrets, "test_vendor_negative_" + _name, _negative_test(_input))


_GENERIC_POSITIVE = [
    ("password_equals", "password=abcdef", "password=" + R),
    ("password_colon", "password: abcdef", "password: " + R),
    ("passwd", "passwd=abcdef", "passwd=" + R),
    ("api_key", "api_key: abcdef", "api_key: " + R),
    ("api_key_hyphen", "api-key=abcdef", "api-key=" + R),
    ("api_key_camel", "apiKey=abcdef", "apiKey=" + R),
    ("access_token", "accessToken=abcdef", "accessToken=" + R),
    ("refresh_token", "refresh_token=abcdef", "refresh_token=" + R),
    ("client_secret_json", '"client_secret":"abcdef"', '"client_secret":"' + R + '"'),
    ("private_key_json", '"private_key":"abcdef"', '"private_key":"' + R + '"'),
    ("session_json", '"session_id": "abcdef"', '"session_id": "' + R + '"'),
    ("aws_secret", "aws_secret_access_key=abcdef", "aws_secret_access_key=" + R),
    ("single_quoted", "password='abcdef'", "password='" + R + "'"),
    ("comma_stop", "token=abcdef, next=1", "token=" + R + ", next=1"),
    ("semicolon_stop", "token=abcdef; next=1", "token=" + R + "; next=1"),
    ("ampersand_stop", "token=abcdef&next=1", "token=" + R + "&next=1"),
    ("short_value", "password=abc", "password=" + R),
    ("spaces", "token = abcdef", "token = " + R),
    ("secret_colon", "secret: abcdef", "secret: " + R),
    ("brace_stop", "token=abcdef}", "token=" + R + "}"),
]
for _name, _input, _expected in _GENERIC_POSITIVE:
    setattr(TestRedactSecrets, "test_generic_positive_" + _name, _positive_test(_input, _expected))

_GENERIC_NEGATIVE = [
    ("empty_unquoted", "password="),
    ("empty_double_quoted", 'password=""'),
    ("empty_single_quoted", "password=''"),
    ("cookiejar", "cookiejar=abcdef"),
    ("tokenizer", "tokenizer=abcdef"),
    ("passwordless", "passwordless=abcdef"),
    ("embedded_token", "mytoken=abcdef"),
    ("no_separator", "token abcdef"),
]
for _name, _input in _GENERIC_NEGATIVE:
    setattr(TestRedactSecrets, "test_generic_negative_" + _name, _negative_test(_input))


def _mixed_case_percent(encoded):
    output = []
    index = 0
    while index < len(encoded):
        if encoded[index] == "%" and index + 2 < len(encoded):
            output.append("%" + encoded[index + 1].swapcase() + encoded[index + 2].swapcase())
            index += 3
        else:
            output.append(encoded[index])
            index += 1
    return "".join(output)


class TestExtraSecrets(PylogcageTestCase):
    def test_raw_exact(self):
        self.assertEqual(redact_secrets("x alpha beta y", extra_secrets=["alpha beta"]), "x " + R + " y")

    def test_raw_case_insensitive(self):
        self.assertEqual(redact_secrets("x ALPHA BETA y", extra_secrets=["alpha beta"]), "x " + R + " y")

    def test_percent_encoded(self):
        secret = "a b+c"
        encoded = urllib.parse.quote(secret, safe="")
        self.assertEqual(redact_secrets("x " + encoded + " y", extra_secrets=[secret]), "x " + R + " y")

    def test_percent_encoded_mixed_case_hex(self):
        secret = "a b+c"
        encoded = _mixed_case_percent(urllib.parse.quote(secret, safe=""))
        self.assertEqual(redact_secrets("x " + encoded + " y", extra_secrets=[secret]), "x " + R + " y")

    def test_plus_form_encoded(self):
        secret = "a b+c"
        encoded = urllib.parse.quote_plus(secret, safe="")
        self.assertEqual(redact_secrets("x " + encoded + " y", extra_secrets=[secret]), "x " + R + " y")

    def test_base64_padded(self):
        secret = "a b+c"
        encoded = base64.b64encode(secret.encode()).decode()
        self.assertEqual(redact_secrets("x " + encoded + " y", extra_secrets=[secret]), "x " + R + " y")

    def test_base64_unpadded(self):
        secret = "a b+c"
        encoded = base64.b64encode(secret.encode()).decode().rstrip("=")
        self.assertEqual(redact_secrets("x " + encoded + " y", extra_secrets=[secret]), "x " + R + " y")

    def test_base64url_padded(self):
        secret = "a b+c"
        encoded = base64.urlsafe_b64encode(secret.encode()).decode()
        self.assertEqual(redact_secrets("x " + encoded + " y", extra_secrets=[secret]), "x " + R + " y")

    def test_base64url_unpadded(self):
        secret = "a b+c"
        encoded = base64.urlsafe_b64encode(secret.encode()).decode().rstrip("=")
        self.assertEqual(redact_secrets("x " + encoded + " y", extra_secrets=[secret]), "x " + R + " y")

    def test_bytes_secret(self):
        encoded = base64.b64encode(b"bytes secret").decode()
        self.assertEqual(redact_secrets("x " + encoded + " y", extra_secrets=[b"bytes secret"]), "x " + R + " y")

    def test_bytearray_secret(self):
        encoded = urllib.parse.quote_plus("bytearray secret", safe="")
        self.assertEqual(redact_secrets("x " + encoded + " y", extra_secrets=[bytearray(b"bytearray secret")]), "x " + R + " y")

    def test_longest_first(self):
        self.assertEqual(redact_secrets("x abcdef y", extra_secrets=["abc", "abcdef"]), "x " + R + " y")

    def test_multiple_secrets(self):
        self.assertEqual(redact_secrets("one two three", extra_secrets=["one", "three"]), R + " two " + R)

    def test_extra_secret_control_obfuscated(self):
        self.assertEqual(redact_secrets("x a\x00b\u200dc y", extra_secrets=["abc"]), "x " + R + " y")

    def test_extra_secret_ansi_obfuscated(self):
        self.assertEqual(redact_secrets("x a\x1b[31mbc y", extra_secrets=["abc"]), "x " + R + " y")

    def test_extra_secret_bidi_obfuscated(self):
        self.assertEqual(redact_secrets("x a\u202eb\u200fc y", extra_secrets=["abc"]), "x " + R + " y")


class TestPii(PylogcageTestCase):
    def test_email_default_not_redacted(self):
        self.assertEqual(redact_secrets("mail user@example.test"), "mail user@example.test")

    def test_email_enabled(self):
        self.assertEqual(redact_secrets("mail user@example.test", redact_pii=True), "mail " + R)

    def test_ssn_default_not_redacted(self):
        self.assertEqual(redact_secrets("ssn 123-45-6789"), "ssn 123-45-6789")

    def test_ssn_enabled(self):
        self.assertEqual(redact_secrets("ssn 123-45-6789", redact_pii=True), "ssn " + R)

    def test_ipv4_enabled(self):
        self.assertEqual(redact_secrets("host 192.168.1.20", redact_pii=True), "host " + R)

    def test_invalid_ipv4_not_redacted(self):
        self.assertEqual(redact_secrets("host 999.168.1.20", redact_pii=True), "host 999.168.1.20")

    def test_luhn_card_enabled(self):
        self.assertEqual(redact_secrets("card 4111 1111 1111 1111", redact_pii=True), "card " + R)

    def test_luhn_card_compact(self):
        self.assertEqual(redact_secrets("card 4111111111111111", redact_pii=True), "card " + R)

    def test_luhn_invalid_not_redacted(self):
        self.assertEqual(redact_secrets("card 4111111111111112", redact_pii=True), "card 4111111111111112")

    def test_ssn_invalid_area_not_redacted(self):
        self.assertEqual(redact_secrets("ssn 000-45-6789", redact_pii=True), "ssn 000-45-6789")

    def test_selective_pii_email_only(self):
        output = redact_secrets("user@example.test 192.168.1.1", pii={"email": True})
        self.assertEqual(output, R + " 192.168.1.1")


class TestRedactionOrdering(PylogcageTestCase):
    def test_redaction_before_truncation_long_password(self):
        secret_value = "a" * 200
        output = sanitize_log_line("start password=" + secret_value + " end", max_length=32)
        self.assertLessEqual(len(output), 32)
        self.assertNotIn(secret_value[:20], output)
        self.assertNotIn("aaaaaaaaaaaaaaaa", output)

    def test_redaction_before_truncation_extra_secret(self):
        secret = "z" * 120
        output = sanitize_log_line("start " + secret + " end", max_length=32, extra_secrets=[secret])
        self.assertLessEqual(len(output), 32)
        self.assertNotIn("zzzzzzzzzzzz", output)

    def test_ansi_obfuscated_password_redacted(self):
        self.assertEqual(sanitize_log_line("password=ab\x1b[31mcdef"), "password=[REDACTED]")

    def test_control_obfuscated_password_redacted(self):
        self.assertEqual(sanitize_log_line("password=ab\x00cdef"), "password=[REDACTED]")

    def test_newline_obfuscated_password_redacted(self):
        self.assertEqual(sanitize_log_line("password=ab\ncdef"), "password=[REDACTED]")

    def test_tab_obfuscated_password_redacted(self):
        self.assertEqual(sanitize_log_line("password=ab\tcdef"), "password=[REDACTED]")

    def test_auth_scheme_control_separators_redacted(self):
        token = "abcdefgh12345678"
        for separator in ("\n", "\r", "\x00", "\u200b"):
            with self.subTest(separator=repr(separator)):
                output = sanitize_log_line("Authorization: Bearer" + separator + token)
                self.assertIn("[REDACTED]", output)
                self.assertNotIn(token, output)

    def test_cookie_line_break_before_value_redacted(self):
        for separator in ("\n", "\r"):
            with self.subTest(separator=repr(separator)):
                output = redact_secrets("Cookie:" + separator + "session=abcdef")
                self.assertIn("[REDACTED]", output)
                self.assertNotIn("session=abcdef", output)

    def test_cookie_header_name_control_obfuscated_redacted(self):
        for header in ("Coo\nkie", "Set-\r\nCookie"):
            with self.subTest(header=repr(header)):
                output = redact_secrets(header + ": session=abcdef")
                self.assertIn("[REDACTED]", output)
                self.assertNotIn("session=abcdef", output)

    def test_extra_secret_control_replaces_space(self):
        for control in ("\n", "\r", "\t", "\x00", "\u200b", "\r\n", "\x00\x00", "\u200b\n"):
            with self.subTest(control=repr(control)):
                output = redact_secrets("x alpha" + control + "beta y", extra_secrets=["alpha beta"])
                self.assertEqual(output, "x " + R + " y")

    def test_linebreak_obfuscated_extra_secret_redacted(self):
        output = sanitize_log_line("x a\nbc y", extra_secrets=["abc"])
        self.assertEqual(output, "x [REDACTED] y")

    def test_zero_width_obfuscated_token_redacted(self):
        token = "abcdefgh12345678"
        obfuscated = token[:5] + "\u200b" + token[5:]
        self.assertEqual(sanitize_log_line("Bearer " + obfuscated), "Bearer [REDACTED]")

    def test_truncation_marker_not_split_after_redaction(self):
        output = sanitize_log_line("password=" + "a" * 100, max_length=16)
        self.assertLessEqual(len(output), 16)
        self.assertNotIn("aaaa", output)


if __name__ == "__main__":
    unittest.main()
