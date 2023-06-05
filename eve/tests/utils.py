# -*- coding: utf-8 -*-

import copy
import hashlib
from datetime import datetime, timedelta

from bson.json_util import dumps
from quart.utils import is_coroutine_function

from eve.tests import TestBase
from eve.utils import (config, date_to_str, debug_error_message, document_etag,
                       extract_key_values, import_from_string, parse_request,
                       querydef, str_to_date, validate_filters, weak_date)


class TestUtils(TestBase):
    """collection, document and home_link methods (and resource_uri, which is
    used by all of them) are tested in 'tests.methods' since we need an active
    flaskapp context
    """

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.dt_fmt = config.DATE_FORMAT
        self.datestr = "Tue, 18 Sep 2012 10:12:30 GMT"
        self.valid = datetime.strptime(self.datestr, self.dt_fmt)
        self.etag = "56eaadbbd9fa287e7270cf13a41083c94f52ab9b"

    async def test_parse_request_where(self):
        self.app.config["DOMAIN"][self.known_resource]["allowed_filters"] = ["ref"]
        async with self.app.test_request_context(path="/"):
            self.assertEqual(parse_request(self.known_resource).where, None)
        async with self.app.test_request_context("/?where=hello"):
            self.assertEqual(parse_request(self.known_resource).where, "hello")

    async def test_parse_request_sort(self):
        async with self.app.test_request_context(path="/"):
            self.assertEqual(parse_request(self.known_resource).sort, None)
        async with self.app.test_request_context("/?sort=hello"):
            self.assertEqual(parse_request(self.known_resource).sort, "hello")

    async def test_parse_request_page(self):
        async with self.app.test_request_context(path="/"):
            self.assertEqual(parse_request(self.known_resource).page, 1)
        async with self.app.test_request_context("/?page=2"):
            self.assertEqual(parse_request(self.known_resource).page, 2)
        async with self.app.test_request_context("/?page=-1"):
            self.assertEqual(parse_request(self.known_resource).page, 1)
        async with self.app.test_request_context("/?page=0"):
            self.assertEqual(parse_request(self.known_resource).page, 1)
        async with self.app.test_request_context("/?page=1.1"):
            self.assertEqual(parse_request(self.known_resource).page, 1)
        async with self.app.test_request_context("/?page=string"):
            self.assertEqual(parse_request(self.known_resource).page, 1)

    async def test_parse_request_max_results(self):
        default = config.PAGINATION_DEFAULT
        limit = config.PAGINATION_LIMIT
        async with self.app.test_request_context(path="/"):
            self.assertEqual(parse_request(self.known_resource).max_results, default)
        async with self.app.test_request_context("/?max_results=%d" % (limit + 1)):
            self.assertEqual(parse_request(self.known_resource).max_results, limit)
        async with self.app.test_request_context("/?max_results=2"):
            self.assertEqual(parse_request(self.known_resource).max_results, 2)
        async with self.app.test_request_context("/?max_results=-1"):
            self.assertEqual(parse_request(self.known_resource).max_results, default)
        async with self.app.test_request_context("/?max_results=0"):
            self.assertEqual(parse_request(self.known_resource).max_results, default)
        async with self.app.test_request_context("/?max_results=1.1"):
            self.assertEqual(parse_request(self.known_resource).max_results, 1)
        async with self.app.test_request_context("/?max_results=string"):
            self.assertEqual(parse_request(self.known_resource).max_results, default)

    async def test_parse_request_max_results_disabled_pagination(self):
        self.app.config["DOMAIN"][self.known_resource]["pagination"] = False
        default = 0
        limit = config.PAGINATION_LIMIT
        async with self.app.test_request_context(path="/"):
            self.assertEqual(parse_request(self.known_resource).max_results, default)
        async with self.app.test_request_context("/?max_results=%d" % (limit + 1)):
            self.assertEqual(parse_request(self.known_resource).max_results, limit + 1)
        async with self.app.test_request_context("/?max_results=2"):
            self.assertEqual(parse_request(self.known_resource).max_results, 2)
        async with self.app.test_request_context("/?max_results=-1"):
            self.assertEqual(parse_request(self.known_resource).max_results, default)
        async with self.app.test_request_context("/?max_results=0"):
            self.assertEqual(parse_request(self.known_resource).max_results, default)
        async with self.app.test_request_context("/?max_results=1.1"):
            self.assertEqual(parse_request(self.known_resource).max_results, 1)
        async with self.app.test_request_context("/?max_results=string"):
            self.assertEqual(parse_request(self.known_resource).max_results, default)

    async def test_parse_request_if_modified_since(self):
        ims = "If-Modified-Since"
        async with self.app.test_request_context(path="/"):
            self.assertEqual(parse_request(self.known_resource).if_modified_since, None)
        async with self.app.test_request_context(path="/", headers=None):
            self.assertEqual(parse_request(self.known_resource).if_modified_since, None)
        async with self.app.test_request_context(path="/", headers={ims: self.datestr}):
            self.assertEqual(
                parse_request(self.known_resource).if_modified_since,
                self.valid + timedelta(seconds=1),
            )
        async with self.app.test_request_context(path="/", headers={ims: "not-a-date"}):
            self.assertRaises(ValueError, parse_request, self.known_resource)
        async with self.app.test_request_context(
            path="/", headers={ims: self.datestr.replace("GMT", "UTC")}
        ):
            self.assertRaises(ValueError, parse_request, self.known_resource)
            self.assertRaises(ValueError, parse_request, self.known_resource)

    async def test_parse_request_if_none_match(self):
        async with self.app.test_request_context(path="/"):
            self.assertEqual(parse_request(self.known_resource).if_none_match, None)
        async with self.app.test_request_context(path="/", headers=None):
            self.assertEqual(parse_request(self.known_resource).if_none_match, None)
        async with self.app.test_request_context(path="/", headers={"If-None-Match": self.etag}):
            self.assertEqual(
                parse_request(self.known_resource).if_none_match, self.etag
            )

    async def test_parse_request_if_match(self):
        async with self.app.test_request_context(path="/"):
            self.assertEqual(parse_request(self.known_resource).if_match, None)
        async with self.app.test_request_context(path="/", headers=None):
            self.assertEqual(parse_request(self.known_resource).if_match, None)
        async with self.app.test_request_context(path="/", headers={"If-Match": self.etag}):
            self.assertEqual(parse_request(self.known_resource).if_match, self.etag)

    async def test_weak_date(self):
        async with self.app.test_request_context(path="/"):
            self.app.config["DATE_FORMAT"] = "%Y-%m-%d"
            self.assertEqual(weak_date(self.datestr), self.valid + timedelta(seconds=1))

    def test_str_to_date(self):
        self.assertEqual(str_to_date(self.datestr), self.valid)
        self.assertRaises(ValueError, str_to_date, "not-a-date")
        self.assertRaises(ValueError, str_to_date, self.datestr.replace("GMT", "UTC"))

    def test_date_to_str(self):
        self.assertEqual(date_to_str(self.valid), self.datestr)

    def test_querydef(self):
        self.assertEqual(querydef(max_results=10), "?max_results=10")
        self.assertEqual(querydef(page=10), "?page=10")
        self.assertEqual(querydef(where="wherepart"), "?where=wherepart")
        self.assertEqual(querydef(sort="sortpart"), "?sort=sortpart")

        self.assertEqual(
            querydef(where="wherepart", sort="sortpart"),
            "?where=wherepart&sort=sortpart",
        )
        self.assertEqual(
            querydef(max_results=10, sort="sortpart"), "?max_results=10&sort=sortpart"
        )

    async def test_document_etag(self):
        test = {"key1": "value1", "another": "value2"}
        challenge = dumps(test, sort_keys=True).encode("utf-8")
        async with self.app.test_request_context(path="/"):
            self.assertEqual(hashlib.sha1(challenge).hexdigest(), document_etag(test))

    async def test_document_etag_ignore_fields(self):
        test = {"key1": "value1", "key2": "value2"}
        test_copy = copy.deepcopy(test)
        ignore_fields = ["key2"]
        test_without_ignore = {"key1": "value1"}
        challenge = dumps(test_without_ignore, sort_keys=True).encode("utf-8")
        async with self.app.test_request_context(path="/"):
            self.assertEqual(
                hashlib.sha1(challenge).hexdigest(), document_etag(test, ignore_fields)
            )
            self.assertEqual(test, test_copy)

        # not required fields can not be present
        test = {"key1": "value1", "key2": "value2"}
        ignore_fields = ["key3"]
        test_without_ignore = {"key1": "value1", "key2": "value2"}
        challenge = dumps(test_without_ignore, sort_keys=True).encode("utf-8")
        async with self.app.test_request_context(path="/"):
            self.assertEqual(
                hashlib.sha1(challenge).hexdigest(), document_etag(test, ignore_fields)
            )

        # ignore fiels nested using doting notation
        test = {"key1": "value1", "dict": {"key2": "value2", "key3": "value3"}}
        test_copy = copy.deepcopy(test)
        ignore_fields = ["dict.key2"]
        test_without_ignore = {"key1": "value1", "dict": {"key3": "value3"}}
        challenge = dumps(test_without_ignore, sort_keys=True).encode("utf-8")
        async with self.app.test_request_context(path="/"):
            self.assertEqual(
                hashlib.sha1(challenge).hexdigest(), document_etag(test, ignore_fields)
            )
            self.assertEqual(test, test_copy)

        # ignore fiels nested using doting notation when a root part of the field is not present
        test = {"key1": "value1", "dict": {"key2": "value2"}}
        ignore_fields = ["dict2.key3"]
        test_without_ignore = {"key1": "value1", "dict": {"key2": "value2"}}
        challenge = dumps(test_without_ignore, sort_keys=True).encode("utf-8")
        async with self.app.test_request_context(path="/"):
            self.assertEqual(
                hashlib.sha1(challenge).hexdigest(), document_etag(test, ignore_fields)
            )

    def test_extract_key_values(self):
        test = {
            "key1": "value1",
            "key2": {"key1": "value2", "nested": {"key1": "value3"}},
        }
        self.assertEqual(
            list(extract_key_values("key1", test)), ["value1", "value2", "value3"]
        )

    async def test_debug_error_message(self):
        async with self.app.test_request_context(path="/"):
            self.app.config["DEBUG"] = False
            self.assertEqual(debug_error_message("An error message"), None)
            self.app.config["DEBUG"] = True
            self.assertEqual(
                debug_error_message("An error message"), "An error message"
            )

    async def test_validate_filters_when_custom_types_are_used(self):
        # Filters validation should operate on the active validator instance,
        # not on Cerberus' standard one. See #1154.
        self.app.config["VALIDATE_FILTERS"] = True
        response, status = await self.get(self.known_resource, query='?where={"tid":"1234"}')
        self.assert400(status)
        self.assertTrue("filter on 'tid' is invalid" in response["_error"]["message"])

        response, status = await self.get(
            self.known_resource, query='?where={"tid":"5a1154523a6bcc1d245e143d"}'
        )
        self.assert200(status)

    async def test_validate_filters(self):
        self.app.config["DOMAIN"][self.known_resource]["allowed_filters"] = []
        async with self.app.test_request_context(path="/"):
            self.assertTrue(
                "key" in (await validate_filters({"key": "val"}, self.known_resource))
            )
            self.assertTrue(
                "key"
                in (await validate_filters({"key": ["val1", "val2"]}, self.known_resource))
            )
            self.assertTrue(
                "key"
                in (await validate_filters(
                    {"key": {"$in": ["val1", "val2"]}}, self.known_resource
                ))
            )
            self.assertTrue(
                "key"
                in (await validate_filters(
                    {"$or": [{"key": "val1"}, {"key": "val2"}]}, self.known_resource
                ))
            )
            self.assertTrue(
                "$or" in (await validate_filters({"$or": "val"}, self.known_resource))
            )
            self.assertTrue(
                "$or" in (await validate_filters({"$or": {"key": "val1"}}, self.known_resource))
            )
            self.assertTrue(
                "$or" in (await validate_filters({"$or": ["val"]}, self.known_resource))
            )

        self.app.config["DOMAIN"][self.known_resource]["allowed_filters"] = ["key"]
        async with self.app.test_request_context(path="/"):
            self.assertTrue(
                (await validate_filters({"key": "val"}, self.known_resource)) is None
            )
            self.assertTrue(
                (await validate_filters({"key": ["val1", "val2"]}, self.known_resource)) is None
            )
            self.assertTrue(
                (await validate_filters(
                    {"key": {"$in": ["val1", "val2"]}}, self.known_resource
                ))
                is None
            )
            self.assertTrue(
                (await validate_filters(
                    {"$or": [{"key": "val1"}, {"key": "val2"}]}, self.known_resource
                ))
                is None
            )

    def test_import_from_string(self):
        dt = import_from_string("datetime.datetime")
        self.assertEqual(dt, datetime)


class DummyEventAsyncIO():
    """
        Even handler that records the call parameters and asserts a check

        Usage::

            app = Eve()
            app.on_my_event = DummyEvent(element_not_deleted)

        In the test::

            assert app.on_my_event.called[0] == expected_param_0
        """

    def __init__(self, check, deepcopy=False):
        """
        :param check: method checking the state of something during the event.
        :type: check: callable returning bool
        :param deepcopy: Do we need to store a copy of the argument calls? In
            some events arguments are changed after the event, so keeping a
            reference to the original object doesn't allow a test to check what
            was passed. The default is False.
        :type deepcopy: bool
        """
        self.__called = None
        self.__check = check
        self.__deepcopy = deepcopy

    async def __call__(self, *args):
        if is_coroutine_function(self.__check):
            assert (await self.__check())
        else:
            assert self.__check()
        # In some method the arguments are changed after the events
        if self.__deepcopy:
            args = copy.deepcopy(args)
        self.__called = args

    @property
    def called(self):
        """
        The results of the call to the event.

        :rtype: It returns None if the event hasn't been called or a tuple with
            the positional arguments of the last call if called.
        """
        return self.__called
