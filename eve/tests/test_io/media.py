import base64
from io import BytesIO
from unittest import TestCase

from bson import ObjectId

from quart.datastructures import FileStorage
from eve import ETAG, ISSUES, STATUS, STATUS_ERR, STATUS_OK
from eve.io.media import MediaStorage
from eve.io.mongo import GridFSMediaStorage
from eve.tests import MONGO_DBNAME, TestBase


class TestMediaStorage(TestCase):
    def test_base_media_storage(self):
        a = MediaStorage()
        self.assertEqual(a.app, None)

        a = MediaStorage("hello")
        self.assertEqual(a.app, "hello")

        self.assertRaises(NotImplementedError, a.get, 1)
        self.assertRaises(NotImplementedError, a.put, "clean", "filename")
        self.assertRaises(NotImplementedError, a.delete, 1)
        self.assertRaises(NotImplementedError, a.exists, 1)


class TestGridFSMediaStorage(TestBase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.url = self.known_resource_url
        self.resource = self.known_resource
        self.headers = [("Content-Type", "multipart/form-data")]
        self.id_field = self.domain[self.resource]["id_field"]
        self.test_field, self.test_value = "ref", "1234567890123456789054321"
        self.clean = b"my file contents"
        self.encoded = base64.b64encode(self.clean).decode()

    def test_gridfs_media_storage_errors(self):
        self.assertRaises(TypeError, GridFSMediaStorage)
        self.assertRaises(TypeError, GridFSMediaStorage, "hello")

    async def test_gridfs_media_storage_post(self):
        # send something different than a file and get an error back
        data = {"media": "not a file"}
        r, s = await self.parse_response(
            await self.test_client.post(self.url, form=data, headers=self.headers)
        )
        self.assertEqual(STATUS_ERR, r[STATUS])

        # validates media fields
        self.assertTrue("must be of media type" in r[ISSUES]["media"])
        # also validates ordinary fields
        self.assertTrue("required" in r[ISSUES][self.test_field])

        r, s = await self._post()
        self.assertEqual(STATUS_OK, r[STATUS])

        # compare original and returned data
        _id = r[self.id_field]
        await self.assertMediaField(_id, self.encoded, self.clean)

        # GET the file at the resource endpoint
        where = 'where={"%s": "%s"}' % (self.id_field, _id)
        r, s = await self.parse_response(await self.test_client.get("%s?%s" % (self.url, where)))
        self.assertEqual(len(r["_items"]), 1)
        returned = r["_items"][0]["media"]

        # returned value is a base64 encoded string
        self.assertEqual(returned, self.encoded)

        # which decodes to the original clean
        self.assertEqual(base64.b64decode(returned.encode()), self.clean)

    async def test_gridfs_media_storage_post_excluded_file_in_result(self):
        # send something different than a file and get an error back
        data = {"media": "not a file"}
        r, s = await self.parse_response(
            await self.test_client.post(self.url, form=data, headers=self.headers)
        )
        self.assertEqual(STATUS_ERR, r[STATUS])

        # validates media fields
        self.assertTrue("must be of media type" in r[ISSUES]["media"])
        # also validates ordinary fields
        self.assertTrue("required" in r[ISSUES][self.test_field])

        r, s = await self._post()
        self.assertEqual(STATUS_OK, r[STATUS])

        self.app.config["RETURN_MEDIA_AS_BASE64_STRING"] = False
        # compare original and returned data
        _id = r[self.id_field]

        # GET the file at the resource endpoint
        where = 'where={"%s": "%s"}' % (self.id_field, _id)
        r, s = await self.parse_response(await self.test_client.get("%s?%s" % (self.url, where)))
        self.assertEqual(len(r["_items"]), 1)
        returned = r["_items"][0]["media"]

        # returned value is a base64 encoded string
        self.assertEqual(returned, None)

    async def test_gridfs_media_storage_post_extended(self):
        r, s = await self._post()
        self.assertEqual(STATUS_OK, r[STATUS])

        # request extended format file response
        self.app.config["EXTENDED_MEDIA_INFO"] = ["content_type", "length"]

        # compare original and returned data
        _id = r[self.id_field]
        await self.assertMediaFieldExtended(_id, self.encoded, self.clean)

        # GET the file at the resource endpoint
        where = 'where={"%s": "%s"}' % (self.id_field, _id)
        r, s = await self.parse_response(await self.test_client.get("%s?%s" % (self.url, where)))
        self.assertEqual(len(r["_items"]), 1)
        returned = r["_items"][0]["media"]

        # returned value is a base64 encoded string
        self.assertEqual(returned["file"], self.encoded)

        # which decodes to the original clean
        self.assertEqual(base64.b64decode(returned["file"].encode()), self.clean)

        # also verify our extended fields
        self.assertEqual(returned["content_type"], "text/plain")
        self.assertEqual(returned["length"], 16)

    async def test_gridfs_media_storage_post_extended_excluded_file_in_result(self):
        r, s = await self._post()
        self.assertEqual(STATUS_OK, r[STATUS])

        # request extended format file response
        self.app.config["EXTENDED_MEDIA_INFO"] = ["content_type", "length"]
        self.app.config["RETURN_MEDIA_AS_BASE64_STRING"] = False
        # compare original and returned data
        _id = r[self.id_field]

        # GET the file at the resource endpoint
        where = 'where={"%s": "%s"}' % (self.id_field, _id)
        r, s = await self.parse_response(await self.test_client.get("%s?%s" % (self.url, where)))
        self.assertEqual(len(r["_items"]), 1)
        returned = r["_items"][0]["media"]

        # returned value is None
        self.assertEqual(returned["file"], None)

        # also verify our extended fields
        self.assertEqual(returned["content_type"], "text/plain")
        self.assertEqual(returned["length"], 16)

    async def test_gridfs_media_storage_put(self):
        r, s = await self._post()
        _id = r[self.id_field]
        etag = r[ETAG]

        # compare original and returned data
        await self.assertMediaField(_id, self.encoded, self.clean)

        async with self.app.test_request_context(path="/"):
            # retrieve media_id
            media_id = await self.assertMediaStored(_id)

        # PUT replaces the file with new one
        clean = b"my new file contents"
        encoded = base64.b64encode(clean).decode()
        test_field, test_value = "ref", "9234567890123456789054321"
        data = {"media": (BytesIO(clean), "test.txt"), test_field: test_value}
        headers = [("Content-Type", "multipart/form-data"), ("If-Match", etag)]

        r, s = await self.parse_response(
            await self.test_client.put(
                ("%s/%s" % (self.url, _id)),
                form={test_field: test_value},
                files={"media": FileStorage(
                    BytesIO(clean),
                    filename="test.txt",
                    content_type="plain/text",
                )},
                headers=headers
            )
        )
        self.assertEqual(STATUS_OK, r[STATUS])

        async with self.app.test_request_context(path="/"):
            # media has been properly stored
            await self.assertMediaStored(_id)

        # compare original and returned data
        r, s = await self.assertMediaField(_id, encoded, clean)

        # and of course, the ordinary field has been updated too
        self.assertEqual(r[test_field], test_value)

        async with self.app.test_request_context(path="/"):
            # previous media doesn't exist anymore (it's been deleted)
            self.assertFalse(await self.app.media.exists(media_id, self.resource))

    async def test_gridfs_media_storage_patch(self):
        r, s = await self._post()
        _id = r[self.id_field]
        etag = r[ETAG]

        # compare original and returned data
        await self.assertMediaField(_id, self.encoded, self.clean)

        async with self.app.test_request_context(path="/"):
            # retrieve media_id
            media_id = await self.assertMediaStored(_id)

        # PATCH replaces the file with new one
        clean = b"my new file contents"
        encoded = base64.b64encode(clean).decode()
        test_field, test_value = "ref", "9234567890123456789054321"
        data = {"media": (BytesIO(clean), "test.txt"), test_field: test_value}
        headers = [("Content-Type", "multipart/form-data"), ("If-Match", etag)]

        r, s = await self.parse_response(
            await self.test_client.patch(
                ("%s/%s" % (self.url, _id)),
                form={test_field: test_value},
                files={"media": FileStorage(
                    BytesIO(clean),
                    filename="test.txt",
                    content_type="text/plain",
                )},
                headers=headers
            )
        )
        self.assertEqual(STATUS_OK, r[STATUS])

        # compare original and returned data
        r, s = await self.assertMediaField(_id, encoded, clean)

        # and of course, the ordinary field has been updated too
        self.assertEqual(r[test_field], test_value)

        async with self.app.test_request_context(path="/"):
            # previous media doesn't exist anymore (it's been deleted)
            self.assertFalse(await self.app.media.exists(media_id, self.resource))

    async def test_gridfs_media_storage_patch_null(self):
        # set 'media' field to 'nullable'
        self.domain[self.known_resource]["schema"]["media"]["nullable"] = True

        response, status = await self._post()
        self.assert201(status)

        _id = response[self.id_field]
        etag = response[ETAG]

        # test that nullable media field can be set to None
        data = {"media": None}
        headers = [("If-Match", etag)]
        response, status = await self.patch(
            ("%s/%s" % (self.url, _id)), data=data, headers=headers
        )
        self.assert200(status)

        response, status = await self.get(self.known_resource, item=_id)
        self.assert200(status)
        self.assertEqual(response["media"], None)

    async def test_gridfs_media_storage_delete(self):
        r, s = await self._post()
        _id = r[self.id_field]
        etag = r[ETAG]

        async with self.app.test_request_context(path="/"):
            # retrieve media_id and compare original and returned data
            await self.assertMediaField(_id, self.encoded, self.clean)

            media_id = await self.assertMediaStored(_id)

        # DELETE deletes both the document and the media file
        headers = [("If-Match", etag)]

        r, s = await self.parse_response(
            await self.test_client.delete(("%s/%s" % (self.url, _id)), headers=headers)
        )
        self.assert204(s)

        async with self.app.test_request_context(path="/"):
            # media doesn't exist anymore (it's been deleted)
            self.assertFalse(await self.app.media.exists(media_id, self.resource))

        # GET returns 404
        r, s = await self.parse_response(await self.test_client.get("%s/%s" % (self.url, _id)))
        self.assert404(s)

    async def test_get_media_can_leverage_projection(self):
        """Test that static projection expose fields other than media
        and client projection on media will work.
        """
        # post a document with *hiding media*
        r, s = await self._post_hide_media()
        _id = r[self.id_field]

        projection = '{"media": 1}'
        response, status = await self.parse_response(
            await self.test_client.get(
                "%s/%s?projection=%s"
                % (self.resource_exclude_media_url, _id, projection)
            )
        )
        self.assert200(status)

        self.assertFalse("title" in response)
        self.assertFalse("ref" in response)
        # client-side projection should work
        self.assertTrue("media" in response)
        self.assertTrue(self.domain[self.known_resource]["id_field"] in response)
        self.assertTrue(self.app.config["ETAG"] in response)
        self.assertTrue(self.app.config["LAST_UPDATED"] in response)
        self.assertTrue(self.app.config["DATE_CREATED"] in response)
        self.assertTrue(r[self.app.config["LAST_UPDATED"]] != self.epoch)
        self.assertTrue(r[self.app.config["DATE_CREATED"]] != self.epoch)

        response, status = await self.parse_response(
            await self.test_client.get("%s/%s" % (self.resource_exclude_media_url, _id))
        )
        self.assert200(status)

        self.assertTrue("title" in response)
        self.assertTrue("ref" in response)
        # not shown without projection
        self.assertFalse("media" in response)
        self.assertTrue(self.domain[self.known_resource]["id_field"] in response)
        self.assertTrue(self.app.config["ETAG"] in response)
        self.assertTrue(self.app.config["LAST_UPDATED"] in response)
        self.assertTrue(self.app.config["DATE_CREATED"] in response)
        self.assertTrue(r[self.app.config["LAST_UPDATED"]] != self.epoch)
        self.assertTrue(r[self.app.config["DATE_CREATED"]] != self.epoch)

    async def test_gridfs_media_storage_delete_projection(self):
        """test that #284 is fixed: If you have a media field, and set
        datasource projection to 0 for that field, the media will not be
        deleted
        """
        r, s = await self._post()
        _id = r[self.id_field]

        async with self.app.test_request_context(path="/"):
            # retrieve media_id and compare original and returned data
            media_id = await self.assertMediaStored(_id)

        self.app.config["DOMAIN"]["contacts"]["datasource"]["projection"] = {"media": 0}

        r, s = await self.parse_response(await self.test_client.get("%s/%s" % (self.url, _id)))
        etag = r[ETAG]

        # DELETE deletes both the document and the media file
        headers = [("If-Match", etag)]

        r, s = await self.parse_response(
            await self.test_client.delete(("%s/%s" % (self.url, _id)), headers=headers)
        )
        self.assert204(s)

        async with self.app.test_request_context(path="/"):
            # media doesn't exist anymore (it's been deleted)
            self.assertFalse(await self.app.media.exists(media_id, self.resource))

        # GET returns 404
        r, s = await self.parse_response(await self.test_client.get("%s/%s" % (self.url, _id)))
        self.assert404(s)

    async def test_gridfs_media_storage_return_url(self):
        self.app._init_media_endpoint()
        self.app.config["RETURN_MEDIA_AS_BASE64_STRING"] = False
        self.app.config["RETURN_MEDIA_AS_URL"] = True

        r, s = await self._post()
        self.assertEqual(STATUS_OK, r[STATUS])
        _id = r[self.id_field]

        # GET the file at the resource endpoint
        where = 'where={"%s": "%s"}' % (self.id_field, _id)
        r, s = await self.parse_response(await self.test_client.get("%s?%s" % (self.url, where)))
        self.assertEqual(len(r["_items"]), 1)
        url = r["_items"][0]["media"]

        async with self.app.test_request_context(path="/"):
            media_id = await self.assertMediaStored(_id)

        self.assertEqual("/media/%s" % media_id, url)
        response = await self.test_client.get(url)
        r_data = await response.get_data()
        self.assertEqual(self.clean, r_data)

    async def test_gridfs_partial_media(self):
        self.app._init_media_endpoint()
        self.app.config["RETURN_MEDIA_AS_BASE64_STRING"] = False
        self.app.config["RETURN_MEDIA_AS_URL"] = True

        r, s = await self._post()
        _id = r[self.id_field]
        where = 'where={"%s": "%s"}' % (self.id_field, _id)
        r, s = await self.parse_response(await self.test_client.get("%s?%s" % (self.url, where)))
        url = r["_items"][0]["media"]

        headers = {"Range": "bytes=0-5"}
        response = await self.test_client.get(url, headers=headers)
        self.assertEqual(self.clean[:6], await response.get_data())
        headers = {"Range": "bytes=5-10"}
        response = await self.test_client.get(url, headers=headers)
        self.assertEqual(self.clean[5:11], await response.get_data())
        headers = {"Range": "bytes=0-999"}
        response = await self.test_client.get(url, headers=headers)
        self.assertEqual(self.clean, await response.get_data())

    async def test_gridfs_media_storage_base_url(self):
        self.app._init_media_endpoint()
        self.app.config["RETURN_MEDIA_AS_BASE64_STRING"] = False
        self.app.config["RETURN_MEDIA_AS_URL"] = True
        self.app.config["MEDIA_BASE_URL"] = "http://s3-us-west-2.amazonaws.com"
        self.app.config["MEDIA_ENDPOINT"] = "foo"

        r, s = await self._post()
        self.assertEqual(STATUS_OK, r[STATUS])
        _id = r[self.id_field]

        # GET the file at the resource endpoint
        where = 'where={"%s": "%s"}' % (self.id_field, _id)
        r, s = await self.parse_response(await self.test_client.get("%s?%s" % (self.url, where)))
        self.assertEqual(len(r["_items"]), 1)
        url = r["_items"][0]["media"]

        async with self.app.test_request_context(path="/"):
            media_id = await self.assertMediaStored(_id)
        self.assertEqual(
            "%s/%s/%s"
            % (
                self.app.config["MEDIA_BASE_URL"],
                self.app.config["MEDIA_ENDPOINT"],
                media_id,
            ),
            url,
        )

    async def test_media_endpoint_supports_CORS(self):
        self.app._init_media_endpoint()
        self.app.config["RETURN_MEDIA_AS_BASE64_STRING"] = False
        self.app.config["RETURN_MEDIA_AS_URL"] = True
        self.app.config["X_DOMAINS"] = "*"

        r, s = await self._post()
        self.assertEqual(STATUS_OK, r[STATUS])
        _id = r[self.id_field]

        async with self.app.test_request_context(path="/"):
            media_id = await self.assertMediaStored(_id)

        methods = ["GET", "OPTIONS"]
        for method in methods:
            method_func = getattr(self.test_client, method.lower())
            r = await method_func(
                "/media/%s" % media_id,
                headers=[("Origin", "http://example.com")],
            )
            self.assert200(r.status_code)
            self.assertEqual(
                r.headers["Access-Control-Allow-Origin"], "http://example.com"
            )
            self.assertEqual(r.headers["Vary"], "Origin")
            self.assertTrue(method in r.headers["Access-Control-Allow-Methods"])

    async def assertMediaField(self, _id, encoded, clean):
        # GET the file at the item endpoint
        r, s = await self.parse_response(await self.test_client.get("%s/%s" % (self.url, _id)))
        returned = r["media"]
        # returned value is a base64 encoded string
        self.assertEqual(returned, encoded)
        # which decodes to the original file clean
        self.assertEqual(base64.b64decode(returned.encode()), clean)
        return r, s

    async def assertMediaFieldExtended(self, _id, encoded, clean):
        # GET the file at the item endpoint
        r, s = await self.parse_response(await self.test_client.get("%s/%s" % (self.url, _id)))
        returned = r["media"]["file"]
        # returned value is a base64 encoded string
        self.assertEqual(returned, encoded)
        # which decodes to the original file clean
        self.assertEqual(base64.b64decode(returned.encode()), clean)
        return r, s

    async def assertMediaStored(self, _id):
        _db = self.connection[MONGO_DBNAME]

        # retrieve media id
        media_id = (await _db.contacts.find_one({self.id_field: ObjectId(_id)}))["media"]

        # verify it's actually stored in the media storage system
        self.assertTrue(await self.app.media.exists(media_id, self.resource))
        return media_id

    async def _post(self):
        # send a file and a required, ordinary field with no issues
        data = {
            self.test_field: self.test_value,
        }

        return await self.parse_response(
            await self.test_client.post(
                self.url,
                form=data,
                headers=self.headers,
                files={"media": FileStorage(
                    BytesIO(self.clean),
                    filename="media",
                    content_type="text/plain",
                )},
            )
        )

        return await self.parse_response(
            await self.test_client.post(self.url, data=data, headers=self.headers)
        )

    async def _post_hide_media(self):
        # send a file and a required, ordinary field with no issues
        data = {
            self.test_field: self.test_value
        }

        return await self.parse_response(
            await self.test_client.post(
                self.resource_exclude_media_url,
                files={"media": FileStorage(
                    BytesIO(self.clean),
                    filename="media",
                    content_type="plain/text"
                )},
                form=data,
                headers=self.headers
            )
        )
