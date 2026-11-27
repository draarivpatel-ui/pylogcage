from __future__ import annotations

import datetime
import math
import os
import unittest
import uuid
from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path

from pylogcage import sanitize_record

from helpers import PylogcageTestCase


class SlottedExample:
    __slots__ = ("alpha", "secret")

    def __init__(self):
        self.alpha = "a\nb"
        self.secret = "password=abc"


class ThrowingProperty:
    @property
    def boom(self):
        raise RuntimeError("boom")


class CustomError(Exception):
    pass


class GroupedError(Exception):
    pass


class BytesPath(os.PathLike):
    def __fspath__(self):
        return b"path-bytes"


class TestRecordScalars(PylogcageTestCase):
    def test_none(self):
        self.assertIsNone(sanitize_record(None))

    def test_bool_true(self):
        self.assertIs(sanitize_record(True), True)

    def test_bool_false(self):
        self.assertIs(sanitize_record(False), False)

    def test_int(self):
        self.assertEqual(sanitize_record(123), 123)

    def test_float_finite(self):
        self.assertEqual(sanitize_record(1.25), 1.25)

    def test_float_nan_string(self):
        self.assertEqual(sanitize_record(float("nan")), "nan")

    def test_float_inf_string(self):
        self.assertEqual(sanitize_record(float("inf")), "inf")

    def test_float_negative_inf_string(self):
        self.assertEqual(sanitize_record(float("-inf")), "-inf")

    def test_string_sanitized(self):
        self.assertEqual(sanitize_record("a\nb\x1b[31m"), "a\\nb")

    def test_string_secret_redacted(self):
        self.assertEqual(sanitize_record("password=abc"), "password=[REDACTED]")

    def test_bytes_plain(self):
        self.assertEqual(sanitize_record(b"abc"), "abc")

    def test_bytes_control(self):
        self.assertEqual(sanitize_record(b"a\nb"), "a\\nb")

    def test_bytes_invalid_utf8(self):
        self.assertEqual(sanitize_record(b"a\xffb"), "a\\xffb")

    def test_bytearray(self):
        self.assertEqual(sanitize_record(bytearray(b"a\nb")), "a\\nb")

    def test_datetime(self):
        value = datetime.datetime(2020, 1, 2, 3, 4, 5)
        self.assertEqual(sanitize_record(value), "2020-01-02T03:04:05")

    def test_date(self):
        self.assertEqual(sanitize_record(datetime.date(2020, 1, 2)), "2020-01-02")

    def test_time(self):
        self.assertEqual(sanitize_record(datetime.time(3, 4, 5)), "03:04:05")

    def test_decimal(self):
        self.assertEqual(sanitize_record(Decimal("1.20")), "1.20")

    def test_decimal_nan(self):
        self.assertEqual(sanitize_record(Decimal("NaN")), "NaN")

    def test_uuid(self):
        value = uuid.UUID(int=0)
        self.assertEqual(sanitize_record(value), "00000000-0000-0000-0000-000000000000")

    def test_path(self):
        self.assertEqual(sanitize_record(Path("a/b")), "a/b")

    def test_bytes_pathlike(self):
        self.assertEqual(sanitize_record(BytesPath()), "path-bytes")


class TestRecordContainers(PylogcageTestCase):
    def test_nested_dict(self):
        self.assertEqual(sanitize_record({"a": {"b": "x\ny"}}), {"a": {"b": "x\\ny"}})

    def test_list(self):
        self.assertEqual(sanitize_record([1, "a\nb"]), [1, "a\\nb"])

    def test_tuple_becomes_list(self):
        self.assertEqual(sanitize_record((1, "a\nb")), [1, "a\\nb"])

    def test_set_sorted(self):
        self.assertEqual(sanitize_record({"b", "a"}), ["a", "b"])

    def test_frozenset_sorted(self):
        self.assertEqual(sanitize_record(frozenset(("b", "a"))), ["a", "b"])

    def test_mixed_nested(self):
        value = {"items": [{"x": "a\nb"}, (1, 2), {"z", "y"}]}
        self.assertEqual(sanitize_record(value), {"items": [{"x": "a\\nb"}, [1, 2], ["y", "z"]]})

    def test_input_dict_not_mutated(self):
        original = {"password": "abc", "nested": {"x": "a\nb"}}
        snapshot = {"password": "abc", "nested": {"x": "a\nb"}}
        output = sanitize_record(original)
        self.assertEqual(original, snapshot)
        self.assertIsNot(output, original)
        self.assertIsNot(output["nested"], original["nested"])

    def test_input_list_not_mutated(self):
        original = ["password=abc"]
        output = sanitize_record(original)
        self.assertEqual(original, ["password=abc"])
        self.assertIsNot(output, original)

    def test_shared_reference_not_circular(self):
        shared = [1]
        output = sanitize_record({"a": shared, "b": shared})
        self.assertEqual(output, {"a": [1], "b": [1]})

    def test_list_circular(self):
        value = []
        value.append(value)
        self.assertEqual(sanitize_record(value), ["[Circular]"])

    def test_dict_circular(self):
        value = {}
        value["self"] = value
        self.assertEqual(sanitize_record(value), {"self": "[Circular]"})

    def test_mutual_circular(self):
        first = {}
        second = {"first": first}
        first["second"] = second
        output = sanitize_record(first)
        self.assertEqual(output["second"]["first"], "[Circular]")

    def test_max_depth(self):
        self.assertEqual(sanitize_record({"a": {"b": {"c": 1}}}, max_depth=2), {"a": {"b": "[MaxDepth]"}})

    def test_max_keys(self):
        output = sanitize_record({"a": 1, "b": 2, "c": 3}, max_keys=2)
        self.assertEqual(output["a"], 1)
        self.assertEqual(output["b"], 2)
        self.assertNotIn("c", output)
        self.assertIn("truncated", output)

    def test_max_keys_stops_unbounded_mapping_iteration(self):
        class EndlessMapping(Mapping):
            def __iter__(self):
                return iter(())

            def __len__(self):
                return 0

            def __getitem__(self, key):
                raise KeyError(key)

            def items(self):
                index = 0
                while True:
                    yield "key" + str(index), index
                    index += 1

        output = sanitize_record(EndlessMapping(), max_keys=4)
        self.assertEqual(output["key0"], 0)
        self.assertEqual(output["key3"], 3)
        self.assertNotIn("key4", output)
        self.assertIn("truncated", output)

    def test_max_sequence_items(self):
        self.assertEqual(sanitize_record([1, 2, 3, 4], max_sequence_items=2), [1, 2, "[Truncated]"])

    def test_max_array_alias(self):
        self.assertEqual(sanitize_record([1, 2, 3], max_array_length=2), [1, 2, "[Truncated]"])

    def test_max_nodes(self):
        output = sanitize_record({"a": [1, 2, 3], "b": 4}, max_nodes=3)
        self.assertIn("[NodeLimit]", repr(output))

    def test_key_cap_counts_dropped_keys(self):
        output = sanitize_record({"constructor": 1, "a": 2, "b": 3}, max_keys=2)
        self.assertNotIn("constructor", output)
        self.assertIn("truncated", output)


class TestRecordKeysAndPaths(PylogcageTestCase):
    def test_sensitive_password_key(self):
        self.assertEqual(sanitize_record({"password": "abc"}), {"password": "[REDACTED]"})

    def test_sensitive_nested_key(self):
        self.assertEqual(sanitize_record({"outer": {"token": "abc"}}), {"outer": {"token": "[REDACTED]"}})

    def test_sensitive_key_case_and_separator(self):
        self.assertEqual(sanitize_record({"Access-Token": "abc"}), {"Access-Token": "[REDACTED]"})

    def test_sensitive_key_control_obfuscated(self):
        self.assertEqual(sanitize_record({"pass\x00word": "abc"}), {"pass\\x00word": "[REDACTED]"})

    def test_additional_sensitive_key(self):
        self.assertEqual(sanitize_record({"session": "abc"}, sensitive_keys=["session"]), {"session": "[REDACTED]"})

    def test_drop_key(self):
        self.assertEqual(sanitize_record({"dropme": 1, "keep": 2}, drop_keys=["dropme"]), {"keep": 2})

    def test_redact_path(self):
        output = sanitize_record({"user": {"public": "x", "session": "y"}}, redact_paths=["user.session"])
        self.assertEqual(output, {"user": {"public": "x", "session": "[REDACTED]"}})

    def test_sensitive_paths_alias(self):
        output = sanitize_record({"user": {"session": "y"}}, sensitive_paths=["user.session"])
        self.assertEqual(output["user"]["session"], "[REDACTED]")

    def test_redact_path_tuple(self):
        output = sanitize_record({"user": {"session": "y"}}, redact_paths=[("user", "session")])
        self.assertEqual(output["user"]["session"], "[REDACTED]")

    def test_drop_path(self):
        output = sanitize_record({"user": {"public": "x", "session": "y"}}, drop_paths=["user.session"])
        self.assertEqual(output, {"user": {"public": "x"}})

    def test_wildcard_path(self):
        output = sanitize_record({"users": {"one": {"token": "a"}, "two": {"token": "b"}}}, redact_paths=["users.*.token"])
        self.assertEqual(output["users"]["one"]["token"], "[REDACTED]")
        self.assertEqual(output["users"]["two"]["token"], "[REDACTED]")

    def test_dangerous_proto_key(self):
        self.assertEqual(sanitize_record({"__proto__": 1, "safe": 2}), {"safe": 2})

    def test_dangerous_constructor_key(self):
        self.assertEqual(sanitize_record({"constructor": 1, "safe": 2}), {"safe": 2})

    def test_dangerous_prototype_key(self):
        self.assertEqual(sanitize_record({"prototype": 1, "safe": 2}), {"safe": 2})

    def test_dangerous_key_case_insensitive(self):
        self.assertEqual(sanitize_record({"Constructor": 1, "safe": 2}), {"safe": 2})

    def test_dangerous_key_control_obfuscated(self):
        self.assertEqual(sanitize_record({"constru\x00ctor": 1, "safe": 2}), {"safe": 2})

    def test_key_newline_escaped(self):
        output = sanitize_record({"a\nb": 1})
        self.assertEqual(output, {"a\\nb": 1})

    def test_duplicate_keys_after_sanitization(self):
        output = sanitize_record({"a\nb": 1, "a\\nb": 2})
        self.assertEqual(len(output), 2)
        self.assertTrue(any("duplicate" in key for key in output))

    def test_non_string_key(self):
        self.assertEqual(sanitize_record({1: "x"}), {"1": "x"})

    def test_none_key(self):
        self.assertEqual(sanitize_record({None: "x"}), {"None": "x"})


class TestRecordObjectsAndExceptions(PylogcageTestCase):
    def test_slotted_object(self):
        output = sanitize_record(SlottedExample())
        self.assertEqual(output["type"], "SlottedExample")
        self.assertEqual(output["alpha"], "a\\nb")
        self.assertEqual(output["secret"], "[REDACTED]")

    def test_throwing_property_not_invoked(self):
        output = sanitize_record(ThrowingProperty())
        self.assertEqual(output, {"type": "ThrowingProperty"})

    def test_plain_object_custom_attribute(self):
        obj = SlottedExample()
        output = sanitize_record(obj)
        self.assertIn("alpha", output)
        self.assertEqual(obj.alpha, "a\nb")

    def test_exception_message(self):
        output = sanitize_record(ValueError("bad password=abc"))
        self.assertEqual(output["type"], "ValueError")
        self.assertEqual(output["message"], "bad password=[REDACTED]")

    def test_exception_args(self):
        output = sanitize_record(ValueError("bad\nvalue"))
        self.assertEqual(output["args"], ["bad\\nvalue"])

    def test_exception_custom_attribute(self):
        exc = CustomError("outer")
        exc.custom = "x\ny"
        output = sanitize_record(exc)
        self.assertEqual(output["custom"], "x\\ny")

    def test_exception_notes(self):
        exc = CustomError("outer")
        exc.__notes__ = ["note password=abc"]
        output = sanitize_record(exc)
        self.assertEqual(output["notes"], ["note password=[REDACTED]"])

    def test_exception_cause(self):
        try:
            try:
                raise ValueError("inner password=abc")
            except ValueError as inner:
                raise CustomError("outer") from inner
        except CustomError as exc:
            output = sanitize_record(exc)
        self.assertEqual(output["cause"]["message"], "inner password=[REDACTED]")

    def test_exception_context(self):
        try:
            try:
                raise ValueError("inner")
            except ValueError:
                raise CustomError("outer")
        except CustomError as exc:
            output = sanitize_record(exc)
        self.assertEqual(output["context"]["type"], "ValueError")

    def test_exception_group_like_exceptions_attribute(self):
        group = GroupedError("group")
        group.exceptions = (ValueError("one"), RuntimeError("two"))
        output = sanitize_record(group)
        self.assertEqual(output["exceptions"][0]["type"], "ValueError")
        self.assertEqual(output["exceptions"][1]["type"], "RuntimeError")

    def test_exception_circular(self):
        exc = CustomError("self")
        exc.self = exc
        output = sanitize_record(exc)
        self.assertEqual(output["self"], "[Circular]")

    def test_slotted_secret_key_redacted(self):
        class SlottedSecret:
            __slots__ = ("password",)
            def __init__(self):
                self.password = "abc"
        self.assertEqual(sanitize_record(SlottedSecret())["password"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
