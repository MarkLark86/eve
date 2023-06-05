import copy
import pytest

import simplejson as json
from bson import ObjectId

from eve import ETAG
from eve.methods.delete import deleteitem_internal
from eve.tests import TestBase
from eve.tests.test_settings import MONGO_DBNAME
from eve.tests.utils import DummyEventAsyncIO
from eve.utils import ParsedRequest


class TestDelete(TestBase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        # Etag used to delete an item (a contact)
        self.etag_headers = [("If-Match", self.item_etag)]

    async def test_unknown_resource(self):
        url = "%s%s/" % (self.unknown_resource_url, self.item_id)
        _, status = await self.delete(url)
        self.assert404(status)

    async def test_bulk_delete_id_field(self):
        etag_check = self.app.config["IF_MATCH"]
        self.app.config["IF_MATCH"] = False
        products, _ = await self.get(self.products)
        list_products_skus = [
            product["parent_product"]
            for product in products["_items"]
            if "parent_product" in product
        ]

        # Deletion of all the product in the first cart
        url = self.child_products_url.replace(
            '<regex("[A-Z]+"):parent_product>', list_products_skus[0]
        )

        _, status = await self.get(url)
        _, status = await self.delete(url)
        self.assert204(status)

        _, status = await self.get(url)

        products_url = "%s/%s" % (self.products, list_products_skus[0])
        _, status = await self.delete(products_url)
        self.assert204(status)
        _, status = await self.get(products_url)
        self.assert404(status)
        _, status = await self.get(self.products)
        self.assert200(status)
        self.app.config["IF_MATCH"] = etag_check

    async def test_delete_from_resource_endpoint(self):
        r, status = await self.delete(self.known_resource_url)
        self.assert204(status)
        r, status = await self.parse_response(await self.test_client.get(self.known_resource_url))
        self.assert200(status)
        self.assertEqual(len(r["_items"]), 0)

    async def test_delete_from_resource_endpoint_write_concern(self):
        # should get a 500 since there's no replicaset on the mongod instance
        self.domain["contacts"]["mongo_write_concern"] = {"w": 2}
        _, status = await self.delete(self.known_resource_url)
        self.assert500(status)

    async def test_delete_from_resource_endpoint_different_resource(self):
        r, status = await self.delete(self.different_resource_url)
        self.assert204(status)
        r, status = await self.parse_response(
            await self.test_client.get(self.different_resource_url)
        )
        self.assert200(status)
        self.assertEqual(len(r["_items"]), 0)

        # deletion of 'users' will still lave 'contacts' untouched (same db
        # collection)
        r, status = await self.parse_response(await self.test_client.get(self.known_resource_url))
        self.assert200(status)
        self.assertEqual(len(r["_items"]), 25)

    async def test_delete_empty_resource(self):
        url = "%s%s/" % (self.empty_resource_url, self.item_id)
        _, status = await self.delete(url)
        self.assert404(status)

    async def test_delete_readonly_resource(self):
        _, status = await self.delete(self.readonly_id_url)
        self.assert405(status)

    async def test_delete_readonly_resource_with_override(self):
        headers = [("X-HTTP-Method-Override", "DELETE")]
        r = await self.test_client.get(self.readonly_resource_url, headers=headers)
        self.assert405(r.status_code)

    async def test_delete_unknown_item(self):
        url = "%s%s/" % (self.known_resource_url, self.unknown_item_id)
        _, status = await self.delete(url)
        self.assert404(status)

    async def test_delete_ifmatch_missing(self):
        _, status = await self.delete(self.item_id_url)
        self.assert428(status)

    async def test_ifmatch_missing_enforce_ifmatch_disabled(self):
        self.app.config["ENFORCE_IF_MATCH"] = False
        r, status = await self.delete(self.item_id_url)
        self.assert204(status)

        r = await self.test_client.get(self.item_id_url)
        self.assert404(r.status_code)

    async def test_delete_ifmatch_disabled(self):
        self.app.config["IF_MATCH"] = False
        _, status = await self.delete(self.item_id_url)
        self.assert204(status)

    async def test_ifmatch_disabled_enforce_ifmatch_disabled(self):
        self.app.config["ENFORCE_IF_MATCH"] = False
        self.app.config["IF_MATCH"] = False
        r, status = await self.delete(self.item_id_url)
        self.assert204(status)

        r = await self.test_client.get(self.item_id_url)
        self.assert404(r.status_code)

    async def test_delete_ifmatch_bad_etag(self):
        _, status = await self.delete(
            self.item_id_url, headers=[("If-Match", "not-quite-right")]
        )
        self.assert412(status)

    async def test_ifmatch_bad_etag_enforce_ifmatch_disabled(self):
        self.app.config["ENFORCE_IF_MATCH"] = False
        _, status = await self.delete(
            self.item_id_url, headers=[("If-Match", "not-quite-right")]
        )
        self.assert412(status)

    async def test_delete(self):
        r, status = await self.delete(self.item_id_url, headers=self.etag_headers)
        self.assert204(status)

        r = await self.test_client.get(self.item_id_url)
        self.assert404(r.status_code)

    async def test_delete_non_existant(self):
        url = self.item_id_url[:-5] + "00000"
        r, status = await self.delete(url, headers=self.etag_headers)
        self.assert204(status)

    async def test_delete_write_concern(self):
        # should get a 500 since there's no replicaset on the mongod instance
        self.domain["contacts"]["mongo_write_concern"] = {"w": 2}
        _, status = await self.delete(
            self.item_id_url, headers=[("If-Match", self.item_etag)]
        )
        self.assert500(status)

    async def test_delete_different_resource(self):
        r, status = await self.delete(
            self.user_id_url, headers=[("If-Match", self.user_etag)]
        )
        self.assert204(status)

        r = await self.test_client.get(self.user_id_url)
        self.assert404(r.status_code)

    async def test_delete_with_post_override(self):
        # POST request with DELETE override turns into a DELETE
        headers = [("X-HTTP-Method-Override", "DELETE"), ("If-Match", self.item_etag)]
        r = await self.test_client.post(self.item_id_url, json={}, headers=headers)
        self.assert204(r.status_code)

    async def test_delete_subresource(self):
        _db = self.connection[MONGO_DBNAME]

        # create random contact
        fake_contact = self.random_contacts(1)[0]
        fake_contact_id = (await _db.contacts.insert_one(fake_contact)).inserted_id

        # grab parent collection count; we will use this later to make sure we
        # didn't delete all the users in the datanase. We add one extra invoice
        # to make sure that the actual count will never be 1 (which would
        # invalidate the test)
        _db.invoices.insert_one({"inv_number": 1})
        response, status = await self.get("invoices")
        invoices = len(response[self.app.config["ITEMS"]])

        # update first invoice to reference the new contact
        _db.invoices.update_one(
            {"_id": ObjectId(self.invoice_id)}, {"$set": {"person": fake_contact_id}}
        )

        # verify that the only document retrieved is referencing the correct
        # parent document
        response, status = await self.get("users/%s/invoices" % fake_contact_id)
        person_id = ObjectId(response[self.app.config["ITEMS"]][0]["person"])
        self.assertEqual(person_id, fake_contact_id)

        # delete all documents at the sub-resource endpoint
        response, status = await self.delete("users/%s/invoices" % fake_contact_id)
        self.assert204(status)

        # verify that the no documents are left at the sub-resource endpoint
        response, status = await self.get("users/%s/invoices" % fake_contact_id)
        self.assertEqual(len(response["_items"]), 0)

        # verify that other documents in the invoices collection have not neen
        # deleted
        response, status = await self.get("invoices")
        self.assertEqual(len(response["_items"]), invoices - 1)

    async def test_delete_subresource_item(self):
        _db = self.connection[MONGO_DBNAME]

        # create random contact
        fake_contact = self.random_contacts(1)[0]
        fake_contact_id = (await _db.contacts.insert_one(fake_contact)).inserted_id

        # update first invoice to reference the new contact
        _db.invoices.update_one(
            {"_id": ObjectId(self.invoice_id)}, {"$set": {"person": fake_contact_id}}
        )

        # GET all invoices by new contact
        response, status = await self.get(
            "users/%s/invoices/%s" % (fake_contact_id, self.invoice_id)
        )
        etag = response[ETAG]

        headers = [("If-Match", etag)]
        response, status = await self.delete(
            "users/%s/invoices/%s" % (fake_contact_id, self.invoice_id), headers=headers
        )
        self.assert204(status)

    async def test_delete_custom_idfield(self):
        response, status = await self.get("products?max_results=1")
        product = response["_items"][0]
        headers = [("If-Match", product[ETAG])]
        response, status = await self.delete("products/%s" % product["sku"], headers=headers)
        self.assert204(status)

    async def test_deleteitem_internal(self):
        # test that deleteitem_internal is available and working properly.
        async with self.app.test_request_context(self.item_id_url):
            r, _, _, status = await deleteitem_internal(
                self.known_resource, concurrency_check=False, **{"_id": self.item_id}
            )
        self.assert204(status)

        r = await self.test_client.get(self.item_id_url)
        self.assert404(r.status_code)

    async def delete(self, url, headers=None):
        r = await self.test_client.delete(url, headers=headers)
        return await self.parse_response(r)


class TestSoftDelete(TestDelete):
    async def asyncSetUp(self):
        await super().asyncSetUp()

        # Enable soft delete
        self.app.config["SOFT_DELETE"] = True
        domain = copy.copy(self.domain)
        for resource, settings in domain.items():
            # rebuild resource settings for soft delete
            del settings["soft_delete"]
            await self.app.register_resource(resource, settings)

        # alias for the configured DELETED field name
        self.deleted_field = self.app.config["DELETED"]

    # TestDelete overrides

    async def test_delete(self):
        """Soft delete should mark an item as deleted and cause subsequent
        requests to return 404 Not Found responses. 404s in response to GET
        requests should include the document in their body with the _deleted
        flag set to True.
        """
        r, status = await self.delete(self.item_id_url, headers=self.etag_headers)
        self.assert204(status)

        r = await self.test_client.get(self.item_id_url)
        data, status = await self.parse_response(r)
        self.assert404(status)

        self.assertEqual(data.get(self.deleted_field), True)
        self.assertNotEqual(data.get("_etag"), self.item_etag)
        # 404 should still include a status and an error field
        self.assertTrue(self.app.config["ERROR"] in data)

    async def test_deleteitem_internal(self):
        """Deleteitem internal should honor soft delete settings."""
        # test that deleteitem_internal is available and working properly.
        async with self.app.test_request_context(self.item_id_url):
            r, _, _, status = await deleteitem_internal(
                self.known_resource, concurrency_check=False, **{"_id": self.item_id}
            )
        self.assert204(status)

        r = await self.test_client.get(self.item_id_url)
        data, status = await self.parse_response(r)
        self.assert404(status)
        self.assertEqual(data.get(self.deleted_field), True)

    async def test_delete_different_resource(self):
        r, status = await self.delete(
            self.user_id_url, headers=[("If-Match", self.user_etag)]
        )
        self.assert204(status)

        r = await self.test_client.get(self.user_id_url)
        data, status = await self.parse_response(r)
        self.assert404(status)
        self.assertEqual(data.get(self.deleted_field), True)

    async def test_delete_from_resource_endpoint(self):
        """Soft deleting an entire resource should mark each individual item
        as deleted, queries to that resource should return no items, and GETs
        on any individual items should return 404 responses.
        """
        # TestDelete deletes resource at known_resource_url, and confirms
        # subsequent queries to the resource return zero items
        await super().test_delete_from_resource_endpoint()

        r = await self.test_client.get(self.item_id_url)
        data, status = await self.parse_response(r)
        self.assert404(status)
        self.assertEqual(data.get(self.deleted_field), True)

    # TetsSoftDelete specific tests

    async def test_restore_softdeleted(self):
        """Sending a PUT or PATCH to a soft deleted document should restore the
        document.
        """

        async def soft_delete_item(etag):
            r, status = await self.delete(self.item_id_url, headers=[("If-Match", etag)])
            self.assert204(status)
            # GET soft deleted etag
            return await self.test_client.get(self.item_id_url)

        # Restore via PATCH
        deleted_etag = (await soft_delete_item(self.item_etag)).headers["ETag"]
        r = await self.test_client.patch(
            self.item_id_url,
            json={},
            headers=[("Content-Type", "application/json"), ("If-Match", deleted_etag)],
        )
        self.assert200(r.status_code)

        r = await self.test_client.get(self.item_id_url)
        self.assert200(r.status_code)
        new_etag = r.headers["ETag"]

        # Restore via PUT
        r = await soft_delete_item(new_etag)
        deleted_etag = r.headers["ETag"]
        restored_doc = {"ref": "1234567890123456789012345"}
        r = await self.test_client.put(
            self.item_id_url,
            json=restored_doc,
            headers=[("Content-Type", "application/json"), ("If-Match", deleted_etag)],
        )
        self.assert200(r.status_code)

        r = await self.test_client.get(self.item_id_url)
        self.assert200(r.status_code)

    async def test_multiple_softdelete(self):
        """After an item has been soft deleted, subsequent DELETEs should
        return a 204 Not Found response.
        """
        r, status = await self.delete(self.item_id_url, headers=self.etag_headers)
        self.assert204(status)
        # GET soft deleted etag
        r = await self.test_client.get(self.item_id_url)
        new_etag = r.headers["ETag"]

        # Second soft DELETE should return 404 Not Found
        r, status = await self.delete(self.item_id_url, headers=[("If-Match", new_etag)])
        self.assert204(status)

    async def test_softdelete_deleted_field(self):
        """The configured 'deleted' field should be added to all documents to indicate
        whether that document has been soft deleted or not.
        """
        r = await self.test_client.get(self.item_id_url)
        data, status = await self.parse_response(r)
        self.assert200(status)
        self.assertEqual(data.get(self.deleted_field), False)

    async def test_softdelete_show_deleted(self):
        """GETs on resource endpoints should include soft deleted items when
        the 'show_deleted' param is included in the query, or when the DELETED
        field is explicitly included in the lookup.
        """
        r, status = await self.delete(self.item_id_url, headers=self.etag_headers)
        self.assert204(status)

        data, status = await self.get(self.known_resource)
        after_softdelete_count = data[self.app.config["META"]]["total"]
        self.assertEqual(after_softdelete_count, self.known_resource_count - 1)

        data, status = await self.get(self.known_resource, query="?show_deleted")
        show_deleted_count = data[self.app.config["META"]]["total"]
        self.assertEqual(show_deleted_count, self.known_resource_count)

        # Test show_deleted with additional queries
        role_query = '?where={"role": "' + self.item["role"] + '"}'
        data, status = await self.get(self.known_resource, query=role_query)
        role_count = data[self.app.config["META"]]["total"]

        data, status = await self.get(self.known_resource, query=role_query + "&show_deleted")
        show_deleted_role_count = data[self.app.config["META"]]["total"]
        self.assertEqual(show_deleted_role_count, role_count + 1)

        # Test explicit _deleted query
        data, status = await self.get(self.known_resource, query='?where={"_deleted": true}')
        deleted_query_count = data[self.app.config["META"]]["total"]
        self.assertEqual(deleted_query_count, 1)

    async def test_softdeleted_embedded_doc(self):
        """Soft deleted documents embedded in other documents should not be
        included. They will resolve to None as if the document was actually
        deleted.
        """
        # Set up and confirm embedded document
        _db = self.connection[MONGO_DBNAME]
        fake_contact = self.random_contacts(1)[0]
        fake_contact_id = (await _db.contacts.insert_one(fake_contact)).inserted_id
        fake_contact_url = self.known_resource_url + "/" + str(fake_contact_id)
        _db.invoices.update_one(
            {"_id": ObjectId(self.invoice_id)}, {"$set": {"person": fake_contact_id}}
        )

        invoices = self.domain["invoices"]
        invoices["embedding"] = True
        invoices["schema"]["person"]["data_relation"]["embeddable"] = True
        embedded = '{"person": 1}'

        r = await self.test_client.get(self.invoice_id_url + "?embedded=%s" % embedded)
        data, status = await self.parse_response(r)
        self.assert200(status)
        self.assertTrue("location" in data["person"])

        # Get embedded doc etag so we can delete it
        r = await self.test_client.get(fake_contact_url)
        embedded_contact_etag = r.headers["ETag"]

        # Delete embedded contact
        data, status = await self.delete(
            fake_contact_url, headers=[("If-Match", embedded_contact_etag)]
        )
        self.assert204(status)

        # embedded 'person' should now be empty
        r = await self.test_client.get(self.invoice_id_url + "?embedded=%s" % embedded)
        data, status = await self.parse_response(r)
        self.assert200(status)
        self.assertEqual(data["person"], None)

    async def test_softdeleted_get_response_skips_embedded_expansion(self):
        """Soft deleted documents should not expand their embedded documents when
        returned in a 404 Not Found response. The deleted document data should
        reflect the state of the document when it was deleted, not change if
        still active embedded documents are updated
        """
        # Confirm embedded document works before delete
        _db = self.connection[MONGO_DBNAME]
        fake_contact = self.random_contacts(1)[0]
        fake_contact_id = (await _db.contacts.insert_one(fake_contact)).inserted_id
        _db.invoices.update_one(
            {"_id": ObjectId(self.invoice_id)}, {"$set": {"person": fake_contact_id}}
        )

        invoices = self.domain["invoices"]
        invoices["embedding"] = True
        invoices["schema"]["person"]["data_relation"]["embeddable"] = True
        embedded = '{"person": 1}'

        r = await self.test_client.get(self.invoice_id_url + "?embedded=%s" % embedded)
        invoice_etag = r.headers["ETag"]
        data, status = await self.parse_response(r)
        self.assert200(status)
        self.assertTrue("location" in data["person"])

        # Soft delete document
        data, status = await self.delete(
            self.invoice_id_url, headers=[("If-Match", invoice_etag)]
        )
        self.assert204(status)

        # Document in 404 should not expand person
        r = await self.test_client.get(self.invoice_id_url + "?embedded=%s" % embedded)
        data, status = await self.parse_response(r)
        self.assert404(status)
        self.assertEqual(data["person"], str(fake_contact_id))

    async def test_softdelete_caching(self):
        """404 Not Found responses after soft delete should be cacheable"""
        # Soft delete item
        r, status = await self.delete(self.item_id_url, headers=self.etag_headers)
        self.assert204(status)

        # delete should have invalidated any previously cached 200 responses
        r = await self.test_client.get(
            self.item_id_url, headers=[("If-None-Match", self.item_etag)]
        )
        self.assert404(r.status_code)

        post_delete_etag = r.headers["ETag"]

        # validate cached 404 response data
        r = status = await self.test_client.get(
            self.item_id_url, headers=[("If-None-Match", post_delete_etag)]
        )
        self.assert304(r.status_code)

    async def test_softdelete_datalayer(self):
        """Soft deleted items should not be returned by find methods in the Eve
        data layer unless show_deleted is explicitly configured in the request,
        the deleted field is included in the lookup, or the operation is 'raw'.
        """
        # Soft delete item
        r, status = await self.delete(self.item_id_url, headers=self.etag_headers)
        self.assert204(status)

        async with self.app.test_request_context(path="/"):
            # find_one should only return item if a request w/ show_deleted ==
            # True is passed or if the deleted field is part of the lookup
            req = ParsedRequest()
            doc = await self.app.data.find_one(self.known_resource, req, _id=self.item_id)
            self.assertEqual(doc, None)

            req.show_deleted = True
            doc = await self.app.data.find_one(self.known_resource, req, _id=self.item_id)
            self.assertNotEqual(doc, None)
            self.assertEqual(doc.get(self.deleted_field), True)

            req.show_deleted = False
            doc = await self.app.data.find_one(
                self.known_resource, req, _id=self.item_id, _deleted=True
            )
            self.assertNotEqual(doc, None)
            self.assertEqual(doc.get(self.deleted_field), True)

            # find_one_raw should always return a document, soft deleted or not
            doc = await self.app.data.find_one_raw(
                self.known_resource, _id=ObjectId(self.item_id)
            )
            self.assertNotEqual(doc, None)
            self.assertEqual(doc.get(self.deleted_field), True)

            # find should only return deleted items if a request with
            # show_deleted == True is passed or if the deleted field is part of
            # the lookup
            req.show_deleted = False
            _, undeleted_count = await self.app.data.find(self.known_resource, req, None)

            req.show_deleted = True
            _, challenge = await self.app.data.find(self.known_resource, req, None)
            self.assertEqual(undeleted_count, challenge - 1)

            req.show_deleted = False
            _, deleted_count = await self.app.data.find(
                self.known_resource, req, {self.deleted_field: True}
            )
            self.assertEqual(deleted_count, 1)

            # find_list_of_ids will return deleted documents if given their id
            ids = await self.app.data.find_list_of_ids(
                self.known_resource, [ObjectId(self.item_id)]
            )

            self.assertEqual(str(ids[0]["_id"]), self.item_id)

    async def test_softdelete_db_fields(self):
        """Documents created when soft delete is enabled should include and
        maintain the DELETED field in the db.
        """
        r = await self.test_client.post(
            self.known_resource_url, json={"ref": "1234567890123456789054321"}
        )
        data, status = await self.parse_response(r)
        self.assert201(status)
        new_item_id = data[self.domain[self.known_resource]["id_field"]]
        new_item_etag = data[self.app.config["ETAG"]]

        async with self.app.test_request_context(path="/"):
            db_stored_doc = await self.app.data.find_one_raw(
                self.known_resource, _id=ObjectId(new_item_id)
            )
            self.assertTrue(self.deleted_field in db_stored_doc)

        # PUT updates to the document should maintain the DELETED field
        r = await self.test_client.put(
            self.known_resource_url + "/" + new_item_id,
            json={"ref": "5432109876543210987654321"},
            headers=[("If-Match", new_item_etag)],
        )
        data, status = await self.parse_response(r)
        self.assert200(status)
        new_item_etag = data[self.app.config["ETAG"]]

        async with self.app.test_request_context(path="/"):
            db_stored_doc = await self.app.data.find_one_raw(
                self.known_resource, _id=ObjectId(new_item_id)
            )
            self.assertTrue(self.deleted_field in db_stored_doc)

        # PATCH updates to the document should maintain the DELETED field
        r = await self.test_client.patch(
            self.known_resource_url + "/" + new_item_id,
            json={"ref": "5555544444333332222211111"},
            headers=[("If-Match", new_item_etag)],
        )
        self.assert200(r.status_code)
        async with self.app.test_request_context(path="/"):
            db_stored_doc = await self.app.data.find_one_raw(
                self.known_resource, _id=ObjectId(new_item_id)
            )
            self.assertTrue(self.deleted_field in db_stored_doc)

    async def test_exclusive_projection(self):
        """Test that when an exclusive projection is used in the 'datasource'
        setting for the resource, enabling soft_deletes does not cause a 500
        error. See #752.
        """
        r = await self.test_client.get("/exclusion?show_deleted")
        data, status = await self.parse_response(r)
        self.assert200(status)

    async def test_exclude_soft_deleted_documents_from_unique_checks(self):
        """Test that soft deleted documents are ignored when validating new
        documents against the 'unique' rule. See #831.
        """
        unique_value = "1234567890123456789054321"

        # 'ref' field has a 'unique' rule applied to it.
        r = await self.test_client.post(self.known_resource_url, json={"ref": unique_value})
        data, status = await self.parse_response(r)
        self.assert201(status)
        new_item_id = data[self.domain[self.known_resource]["id_field"]]
        new_item_etag = data[self.app.config["ETAG"]]

        # we can't post a new document with the same value.
        r = await self.test_client.post(self.known_resource_url, json={"ref": unique_value})
        data, status = await self.parse_response(r)
        self.assert422(status)

        # we now soft delete the document.
        r = await self.test_client.delete(
            self.known_resource_url + "/" + new_item_id,
            headers=[("If-Match", new_item_etag)],
        )
        data, status = await self.parse_response(r)
        self.assert204(status)

        # posting a new document with the same value for 'ref'
        # is now possible.
        r = await self.test_client.post(self.known_resource_url, json={"ref": unique_value})
        data, status = await self.parse_response(r)
        self.assert201(status)


class TestResourceSpecificSoftDelete(TestBase):
    async def asyncSetUp(self):
        await super().asyncSetUp()

        # Enable soft delete for one resource
        domain = copy.copy(self.domain)
        resource_settings = domain[self.known_resource]
        resource_settings["soft_delete"] = True
        await self.app.register_resource(self.known_resource, resource_settings)

        self.deleted_field = self.app.config["DELETED"]

        # Etag used to delete an item (a contact)
        self.etag_headers = [("If-Match", self.item_etag)]

    async def test_resource_specific_softdelete(self):
        """Resource level soft delete configuration should override
        application configuration.
        """
        # Confirm soft delete is enabled for known resource.
        data, status = await self.delete(self.item_id_url, headers=self.etag_headers)
        self.assert204(status)

        r = await self.test_client.get(self.item_id_url)
        data, status = await self.parse_response(r)
        self.assert404(status)
        self.assertEqual(data.get(self.deleted_field), True)

        # DELETE on other resources should be hard deletes
        data, status = await self.delete(
            self.invoice_id_url, headers=[("If-Match", self.invoice_etag)]
        )
        self.assert204(status)

        r = await self.test_client.get(self.invoice_id_url)
        data, status = await self.parse_response(r)
        self.assert404(status)
        self.assertTrue(self.deleted_field not in data)


class TestDeleteEvents(TestBase):
    async def test_on_pre_DELETE_for_item(self):
        devent = DummyEventAsyncIO(self.before_delete)
        self.app.on_pre_DELETE += devent
        await self.delete_item()
        self.assertEqual("contacts", devent.called[0])
        self.assertFalse(devent.called[1] is None)

    async def test_on_pre_DELETE_resource_for_item(self):
        devent = DummyEventAsyncIO(self.before_delete)
        self.app.on_pre_DELETE_contacts += devent
        await self.delete_item()
        self.assertFalse(devent.called is None)

    async def test_on_pre_DELETE_for_resource(self):
        devent = DummyEventAsyncIO(self.before_delete)
        self.app.on_pre_DELETE += devent
        await self.delete_resource()
        self.assertFalse(devent.called is None)

    async def test_on_pre_DELETE_resource_for_resource(self):
        devent = DummyEventAsyncIO(self.before_delete)
        self.app.on_pre_DELETE_contacts += devent
        await self.delete_resource()
        self.assertFalse(devent.called is None)

    async def test_on_pre_DELETE_dynamic_filter(self):
        async def filter_this(resource, request, lookup):
            lookup["_id"] = self.unknown_item_id

        self.app.on_pre_DELETE += filter_this
        # Would normally delete the known document; will return 204 instead.
        r, s = await self.parse_response(await self.delete_item())
        self.assert204(s)

    async def test_on_post_DELETE_for_item(self):
        devent = DummyEventAsyncIO(self.after_delete)
        self.app.on_post_DELETE += devent
        await self.delete_item()
        self.assertFalse(devent.called is None)

    async def test_on_post_DELETE_resource_for_item(self):
        devent = DummyEventAsyncIO(self.after_delete)
        self.app.on_post_DELETE_contacts += devent
        await self.delete_item()
        self.assertFalse(devent.called is None)

    async def test_on_post_DELETE_for_resource(self):
        devent = DummyEventAsyncIO(self.after_delete)
        self.app.on_post_DELETE += devent
        await self.delete_resource()
        self.assertFalse(devent.called is None)

    async def test_on_post_DELETE_resource_for_resource(self):
        devent = DummyEventAsyncIO(self.after_delete)
        self.app.on_post_DELETE_contacts += devent
        await self.delete_resource()
        self.assertFalse(devent.called is None)

    async def test_on_delete_resource(self):
        devent1 = DummyEventAsyncIO(self.before_delete)
        self.app.on_delete_resource += devent1
        devent2 = DummyEventAsyncIO(self.before_delete)
        self.app.on_delete_resource_originals += devent2
        await self.delete_resource()
        self.assertEqual(("contacts",), devent1.called)
        self.assertFalse(devent2.called is None)

    async def test_on_delete_resource_contacts(self):
        devent1 = DummyEventAsyncIO(self.before_delete)
        self.app.on_delete_resource_contacts += devent1
        devent2 = DummyEventAsyncIO(self.before_delete)
        self.app.on_delete_resource_originals_contacts += devent2
        await self.delete_resource()
        self.assertEqual(tuple(), devent1.called)
        self.assertFalse(devent2.called is None)

    async def test_on_deleted_resource_contacts(self):
        devent = DummyEventAsyncIO(self.after_delete)
        self.app.on_deleted_resource_contacts += devent
        await self.delete_resource()
        self.assertEqual(tuple(), devent.called)

    async def test_on_delete_item(self):
        devent = DummyEventAsyncIO(self.before_delete)
        self.app.on_delete_item += devent
        await self.delete_item()
        self.assertEqual("contacts", devent.called[0])
        id_field = self.domain["contacts"]["id_field"]
        self.assertEqual(self.item_id, str(devent.called[1][id_field]))

    async def test_on_delete_item_contacts(self):
        devent = DummyEventAsyncIO(self.before_delete)
        self.app.on_delete_item_contacts += devent
        await self.delete_item()
        id_field = self.domain["contacts"]["id_field"]
        self.assertEqual(self.item_id, str(devent.called[0][id_field]))

    async def test_on_deleted_item(self):
        devent = DummyEventAsyncIO(self.after_delete)
        self.app.on_deleted_item += devent
        await self.delete_item()
        self.assertEqual("contacts", devent.called[0])
        id_field = self.domain["contacts"]["id_field"]
        self.assertEqual(self.item_id, str(devent.called[1][id_field]))

    async def test_on_deleted_item_contacts(self):
        devent = DummyEventAsyncIO(self.after_delete)
        self.app.on_deleted_item_contacts += devent
        await self.delete_item()
        id_field = self.domain["contacts"]["id_field"]
        self.assertEqual(self.item_id, str(devent.called[0][id_field]))

    async def delete_resource(self):
        await self.test_client.delete(self.known_resource_url)

    async def delete_item(self):
        return await self.test_client.delete(
            self.item_id_url, headers=[("If-Match", self.item_etag)]
        )

    async def before_delete(self):
        db = self.connection[MONGO_DBNAME]
        return (await db.contacts.find_one(ObjectId(self.item_id))) is not None

    async def after_delete(self):
        return not await self.before_delete()
