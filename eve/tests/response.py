# -*- coding: utf-8 -*-

import os
from ast import literal_eval

import simplejson as json

import eve
from eve.tests import TestBase


class TestResponse(TestBase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.r = await self.test_client.get("/%s/" % self.empty_resource)

    async def test_response_data(self):
        response = None
        try:
            response = literal_eval((await self.r.get_data()).decode())
        except Exception:
            self.fail("standard response cannot be converted to a dict")
        self.assertTrue(isinstance(response, dict))

    async def test_response_object(self):
        response = literal_eval((await self.r.get_data()).decode())
        self.assertTrue(isinstance(response, dict))
        self.assertEqual(len(response), 3)

        resource = response.get("_items")
        self.assertTrue(isinstance(resource, list))
        links = response.get("_links")
        self.assertTrue(isinstance(links, dict))
        meta = response.get("_meta")
        self.assertTrue(isinstance(meta, dict))

    async def test_response_pretty(self):
        # check if pretty printing was successful by checking the length of the
        # response since pretty printing the respone makes it longer and not
        # type dict anymore
        self.r = await self.test_client.get("/%s/?pretty" % self.empty_resource)
        response = (await self.r.get_data()).decode()
        self.assertEqual(len(response), 300)


class TestNoHateoas(TestBase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.app.config["HATEOAS"] = False
        self.domain[self.known_resource]["hateoas"] = False

    async def test_get_no_hateoas_resource(self):
        r = await self.test_client.get(self.known_resource_url)
        response = json.loads((await r.get_data()).decode())
        self.assertTrue(isinstance(response, dict))
        self.assertEqual(len(response["_items"]), 25)
        item = response["_items"][0]
        self.assertTrue(isinstance(item, dict))
        self.assertTrue("_links" not in response)

    async def test_get_no_hateoas_item(self):
        r = await self.test_client.get(self.item_id_url)
        response = json.loads((await r.get_data()).decode())
        self.assertTrue(isinstance(response, dict))
        self.assertTrue("_links" not in response)

    async def test_get_no_hateoas_homepage(self):
        r = await self.test_client.get("/")
        self.assert200(r.status_code)

    async def test_get_no_hateoas_homepage_reply(self):
        r = await self.test_client.get("/")
        resp = json.loads((await r.get_data()).decode())
        self.assertEqual(resp, {})

        self.app.config["INFO"] = "_info"

        r = await self.test_client.get("/")
        resp = json.loads((await r.get_data()).decode())
        self.assertEqual(resp["_info"]["server"], "Eve")
        self.assertEqual(resp["_info"]["version"], eve.__version__)

        settings_file = os.path.join(self.this_directory, "test_version.py")
        self.app = eve.Eve(settings=settings_file)
        await self.app.init_resources()
        self.app.config["INFO"] = "_info"

        r = await self.app.test_client().get("/v1")
        resp = json.loads((await r.get_data()).decode())
        self.assertEqual(resp["_info"]["api_version"], self.app.config["API_VERSION"])
        self.assertEqual(resp["_info"]["server"], "Eve")
        self.assertEqual(resp["_info"]["version"], eve.__version__)

    async def test_post_no_hateoas(self):
        data = {"item1": json.dumps({"ref": "1234567890123456789054321"})}
        headers = [("Content-Type", "application/x-www-form-urlencoded")]
        r = await self.test_client.post(self.known_resource_url, data=data, headers=headers)
        response = json.loads((await r.get_data()).decode())
        self.assertTrue("_links" not in response)

    async def test_patch_no_hateoas(self):
        data = {"item1": json.dumps({"ref": "0000000000000000000000000"})}
        headers = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("If-Match", self.item_etag),
        ]
        r = await self.test_client.patch(self.item_id_url, data=data, headers=headers)
        response = json.loads((await r.get_data()).decode())
        self.assertTrue("_links" not in response)
