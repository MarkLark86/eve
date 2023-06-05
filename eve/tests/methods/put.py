import pytest
import simplejson as json
from bson import ObjectId
from bson.dbref import DBRef

from eve import ETAG, ISSUES, LAST_UPDATED, STATUS, STATUS_OK
from eve.methods.put import put_internal
from eve.tests import TestBase
from eve.tests.test_settings import MONGO_DBNAME
from eve.tests.utils import DummyEventAsyncIO


class TestPut(TestBase):
    # TODO consider making a base codebase out of 'patch' and 'put' tests
    async def test_put_to_resource_endpoint(self):
        _, status = await self.put(self.known_resource_url, data={})
        self.assert405(status)

    async def test_readonly_resource(self):
        _, status = await self.put(self.readonly_id_url, data={})
        self.assert405(status)

    async def test_by_name(self):
        _, status = await self.put(self.item_name_url, data={"key1": "value1"})
        self.assert405(status)

    async def test_ifmatch_missing(self):
        _, status = await self.put(self.item_id_url, data={"key1": "value1"})
        self.assert428(status)

    def test_ifmatch_missing_enforce_ifmatch_disabled(self):
        self.app.config["ENFORCE_IF_MATCH"] = False

    async def test_ifmatch_disabled(self):
        self.app.config["IF_MATCH"] = False
        r, status = await self.put(
            self.item_id_url, data={"ref": "1234567890123456789012345"}
        )
        self.assert200(status)
        self.assertTrue(ETAG not in r)

    async def test_ifmatch_disabled_enforce_ifmatch_disabled(self):
        self.app.config["IF_MATCH"] = False
        self.app.config["ENFORCE_IF_MATCH"] = False
        r, status = await self.put(
            self.item_id_url, data={"ref": "1234567890123456789012345"}
        )
        self.assert200(status)
        self.assertTrue(ETAG not in r)

    async def test_ifmatch_bad_etag(self):
        _, status = await self.put(
            self.item_id_url,
            data={"key1": "value1"},
            headers=[("If-Match", "not-quite-right")],
        )
        self.assert412(status)

    async def test_ifmatch_bad_etag_enforce_ifmatch_disabled(self):
        self.app.config["ENFORCE_IF_MATCH"] = False
        _, status = await self.put(
            self.item_id_url,
            data={"key1": "value1"},
            headers=[("If-Match", "not-quite-right")],
        )
        self.assert412(status)

    async def test_unique_value(self):
        r, status = await self.put(
            self.item_id_url,
            data={"ref": "%s" % self.alt_ref},
            headers=[("If-Match", self.item_etag)],
        )
        self.assertValidationErrorStatus(status)
        self.assertValidationError(
            r, {"ref": "value '%s' is not unique" % self.alt_ref}
        )

    async def test_allow_unknown(self):
        changes = {"unknown": "unknown"}
        r, status = await self.put(
            self.item_id_url, data=changes, headers=[("If-Match", self.item_etag)]
        )
        self.assertValidationErrorStatus(status)
        self.assertValidationError(r, {"unknown": "unknown field"})
        self.app.config["DOMAIN"][self.known_resource]["allow_unknown"] = True
        changes = {"unknown": "unknown", "ref": "1234567890123456789012345"}
        r, status = await self.put(
            self.item_id_url, data=changes, headers=[("If-Match", self.item_etag)]
        )
        self.assert200(status)
        self.assertPutResponse(r, self.item_id)

    async def test_put_x_www_form_urlencoded(self):
        field = "ref"
        test_value = "1234567890123456789012345"
        changes = {field: test_value}
        headers = [("If-Match", self.item_etag)]
        r, status = await self.parse_response(
            await self.test_client.put(self.item_id_url, form=changes, headers=headers)
        )
        self.assert200(status)
        self.assertTrue("OK" in r[STATUS])

    async def test_put_x_www_form_urlencoded_number_serialization(self):
        del self.domain["contacts"]["schema"]["ref"]["required"]
        field = "anumber"
        test_value = 41
        changes = {field: test_value}
        headers = [("If-Match", self.item_etag)]
        r, status = await self.parse_response(
            await self.test_client.put(self.item_id_url, form=changes, headers=headers)
        )
        self.assert200(status)
        self.assertTrue("OK" in r[STATUS])

    async def test_put_referential_integrity(self):
        data = {"person": self.unknown_item_id}
        headers = [("If-Match", self.invoice_etag)]
        r, status = await self.put(self.invoice_id_url, data=data, headers=headers)
        self.assertValidationErrorStatus(status)
        expected = "value '%s' must exist in resource '%s', field '%s'" % (
            self.unknown_item_id,
            "contacts",
            self.domain["contacts"]["id_field"],
        )
        self.assertValidationError(r, {"person": expected})

        data = {"person": self.item_id}
        r, status = await self.put(self.invoice_id_url, data=data, headers=headers)
        self.assert200(status)
        self.assertPutResponse(r, self.invoice_id, "invoices")

    async def test_put_referential_integrity_list(self):
        data = {"invoicing_contacts": [self.item_id, self.unknown_item_id]}
        headers = [("If-Match", self.invoice_etag)]
        r, status = await self.put(self.invoice_id_url, data=data, headers=headers)
        self.assertValidationErrorStatus(status)
        expected = "value '%s' must exist in resource '%s', field '%s'" % (
            self.unknown_item_id,
            "contacts",
            self.domain["contacts"]["id_field"],
        )
        self.assertValidationError(r, {"invoicing_contacts": expected})

        data = {"invoicing_contacts": [self.item_id, self.item_id]}
        r, status = await self.put(self.invoice_id_url, data=data, headers=headers)
        self.assert200(status)
        self.assertPutResponse(r, self.invoice_id, "invoices")

    async def test_put_write_concern_success(self):
        # 0 and 1 are the only valid values for 'w' on our mongod instance (1
        # is the default)
        self.domain["contacts"]["mongo_write_concern"] = {"w": 0}
        field = "ref"
        test_value = "X234567890123456789012345"
        changes = {field: test_value}
        _, status = await self.put(
            self.item_id_url, data=changes, headers=[("If-Match", self.item_etag)]
        )
        self.assert200(status)

    async def test_put_write_concern_fail(self):
        # should get a 500 since there's no replicaset on the mongod instance
        self.domain["contacts"]["mongo_write_concern"] = {"w": 2}
        field = "ref"
        test_value = "X234567890123456789012345"
        changes = {field: test_value}
        _, status = await self.put(
            self.item_id_url, data=changes, headers=[("If-Match", self.item_etag)]
        )
        self.assert500(status)

    async def test_put_string(self):
        field = "ref"
        test_value = "1234567890123456789012345"
        changes = {field: test_value}
        r = await self.perform_put(changes)
        db_value = await self.compare_put_with_get(field, r)
        self.assertEqual(db_value, test_value)

    async def test_put_with_post_override(self):
        # POST request with PUT override turns into a PUT
        field = "ref"
        test_value = "1234567890123456789012345"
        changes = {field: test_value}
        headers = [
            ("X-HTTP-Method-Override", "PUT"),
            ("If-Match", self.item_etag),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ]
        r = await self.test_client.post(self.item_id_url, form=changes, headers=headers)
        self.assert200(r.status_code)
        self.assertPutResponse(json.loads(await r.get_data()), self.item_id)

    async def test_put_sets_default_value_when_field_not_provided_neither_persisted(self):
        """
        Test that when replacing a document, any field that has default values
        defined in the schema is set according to the schema default when
        the current persisted document doesn't have the field value set.
        """
        test_field = "unsetted_default_value_field"
        test_value = self.domain["contacts"]["schema"]["unsetted_default_value_field"][
            "default"
        ]
        data = {"ref": "9234567890123456789054321"}
        r = await self.perform_put(data)
        db_value = await self.compare_put_with_get(test_field, r)
        self.assertEqual(test_value, db_value)

    async def test_put_sets_default_value_when_field_not_provided_but_persisted(self):
        """
        Test that when replacing a document, any field that has default values
        defined in the schema is set according to the schema default when
        the current persisted document already had the field value set.

        This effectively makes impossible to delete fields with default values
        in the schema using a PUT request.
        """
        test_field = "title"
        test_value = "Mr."
        data = {"ref": "9234567890123456789054321"}
        r = await self.perform_put(data)
        db_value = await self.compare_put_with_get(test_field, r)
        self.assertEqual(test_value, db_value)

    async def test_put_removes_non_provided_non_default_field(self):
        """
        Test that when replacing a document, any field that has doesn't have
        a default value defined in the schema and has not been provided in
        the request will be effectively deleted in the replaced version.

        """
        data = {"ref": "9234567890123456789054321"}
        r = await self.perform_put(data)

        item_id = r[self.domain[self.known_resource]["id_field"]]
        raw_r = await self.test_client.get("%s/%s" % (self.known_resource_url, item_id))
        item, status = await self.parse_response(raw_r)

        meta_fields = ["_etag", "_updated", "_id", "_links", "_created"]
        explicitly_set_fields = ["ref"]
        fields_with_defaults = [
            "unsetted_default_value_field",
            "ref",
            "dependency_field1",
            "title",
            "read_only_field",
        ]

        self.assertEqual(
            set(meta_fields + explicitly_set_fields + fields_with_defaults),
            set(item.keys()),
        )

    async def test_put_readonly_value_same(self):
        data = {
            "ref": self.item["ref"],
            "read_only_field": self.item["read_only_field"],
        }
        r, status = await self.put(
            self.item_id_url, data=data, headers=[("If-Match", self.item_etag)]
        )
        self.assert200(status)

    async def test_put_readonly_value_different(self):
        field = "read_only_field"
        data = {"ref": self.item["ref"], field: "somethingelse"}
        r, status = await self.put(
            self.item_id_url, data=data, headers=[("If-Match", self.item_etag)]
        )
        self.assert422(status)
        self.assertValidationError(r, {field: "field is read-only"})

    async def test_put_subresource(self):
        _db = self.connection[MONGO_DBNAME]
        self.app.config["BANDWIDTH_SAVER"] = False

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

        data = {"inv_number": "new_number"}
        headers = [("If-Match", etag)]
        response, status = await self.put(
            "users/%s/invoices/%s" % (fake_contact_id, self.invoice_id),
            data=data,
            headers=headers,
        )
        self.assert200(status)
        self.assertPutResponse(response, self.invoice_id, "peopleinvoices")
        self.assertEqual(response.get("person"), str(fake_contact_id))

    async def test_put_dbref_subresource(self):
        _db = self.connection[MONGO_DBNAME]
        self.app.config["BANDWIDTH_SAVER"] = False

        # create random contact
        fake_contact = self.random_contacts(1)[0]
        fake_contact_id = (await _db.contacts.insert_one(fake_contact)).inserted_id

        # update first invoice to reference the new contact
        _db.invoices.update_one(
            {"_id": ObjectId(self.invoice_id)},
            {
                "$set": {
                    "person": fake_contact_id,
                    "persondbref": DBRef("contacts", ObjectId(fake_contact_id)),
                }
            },
        )

        # GET all invoices by new contact
        response, status = await self.get(
            "users/%s/invoices/%s" % (fake_contact_id, self.invoice_id)
        )

        self.assertEqual(response.get("persondbref")["$id"], str(fake_contact_id))

        etag = response[ETAG]

        data = {"inv_number": "new_number"}
        headers = [("If-Match", etag)]
        response, status = await self.put(
            "users/%s/invoices/%s" % (fake_contact_id, self.invoice_id),
            data=data,
            headers=headers,
        )

        self.assert200(status)
        self.assertPutResponse(response, self.invoice_id, "peopleinvoices")

    async def test_put_bandwidth_saver(self):
        changes = {"ref": "1234567890123456789012345"}

        # bandwidth_saver is on by default
        self.assertTrue(self.app.config["BANDWIDTH_SAVER"])
        r = await self.perform_put(changes)
        self.assertFalse("ref" in r)
        db_value = await self.compare_put_with_get(self.app.config["ETAG"], r)
        self.assertEqual(db_value, r[self.app.config["ETAG"]])
        self.item_etag = r[self.app.config["ETAG"]]

        # test return all fields (bandwidth_saver off)
        self.app.config["BANDWIDTH_SAVER"] = False
        r = await self.perform_put(changes)
        self.assertTrue("ref" in r)
        db_value = await self.compare_put_with_get(self.app.config["ETAG"], r)
        self.assertEqual(db_value, r[self.app.config["ETAG"]])

    async def test_put_bandwidth_saver_credit_rule_broken(self):
        _db = self.connection[MONGO_DBNAME]
        rule = {
            "amount": 300.0,
            "duration": "months",
            "name": "Testing BANDWIDTH_SAVER=False",
            "start": "2020-03-28T06:00:00 UTC",
        }
        rule_id = (await _db.credit_rules.insert_one(rule)).inserted_id
        rule_url = "credit_rules/%s/" % (rule_id)
        changes = {
            "amount": 120.0,
            "duration": "months",
            "start": "2020-04-01T00:00:00 UTC",
        }
        response, _ = await self.get("credit_rules/%s/" % (rule_id))
        etag = response[ETAG]
        # bandwidth_saver is on by default
        self.assertTrue(self.app.config["BANDWIDTH_SAVER"])
        self.assertTrue(self.app.config["PROJECTION"])
        r, status = await self.put(rule_url, data=changes, headers=[("If-Match", etag)])
        self.assert200(status)
        self.assertPutResponse(r, "%s" % (rule_id))
        self.assertFalse("amount" in r)
        etag = r[self.app.config["ETAG"]]
        r, _ = await self.get(rule_url, "")
        self.assertEqual(etag, r[self.app.config["ETAG"]])

        # test return all fields (bandwidth_saver off)
        self.app.config["BANDWIDTH_SAVER"] = False
        changes["name"] = "Give it all to me!"
        r, status = await self.put(rule_url, data=changes, headers=[("If-Match", etag)])
        self.assert200(status)
        self.assertPutResponse(r, "%s" % (rule_id))
        self.assertTrue(
            all(["amount" in r, "duration" in r, "name" in r, "start" in r]),
            'One or more of "amount", "duration", "name", "start" is missing.',
        )
        self.assertTrue(r["name"] == "Give it all to me!")
        etag = r[self.app.config["ETAG"]]
        r, status = await self.get(rule_url, "")
        self.assertEqual(etag, r[self.app.config["ETAG"]])

    async def test_put_dependency_fields_with_default(self):
        # Test that if a dependency is missing but has a default value then the
        # field is still accepted. See #353.
        del self.domain["contacts"]["schema"]["ref"]["required"]
        field = "dependency_field2"
        test_value = "a value"
        changes = {field: test_value}
        r = await self.perform_put(changes)
        db_value = await self.compare_put_with_get(field, r)
        self.assertEqual(db_value, test_value)

    async def test_put_dependency_fields_with_wrong_value(self):
        # Test that if a dependency is not met, the put is refused
        del self.domain["contacts"]["schema"]["ref"]["required"]
        r, status = await self.put(
            self.item_id_url,
            data={"dependency_field3": "value"},
            headers=[("If-Match", self.item_etag)],
        )
        self.assert422(status)
        r, status = await self.put(
            self.item_id_url,
            data={"dependency_field1": "value", "dependency_field3": "value"},
            headers=[("If-Match", self.item_etag)],
        )
        self.assert200(status)

    async def test_put_custom_idfield(self):
        product = {"title": "Awesome Hypercube"}
        r, status = await self.put("products/FOOBAR", data=product)
        self.assert201(status)

    async def test_put_internal(self):
        # test that put_internal is available and working properly.
        test_field = "ref"
        test_value = "9876543210987654321098765"
        data = {test_field: test_value}
        async with self.app.test_request_context(self.item_id_url):
            r, _, _, status = await put_internal(
                self.known_resource,
                data,
                concurrency_check=False,
                **{"_id": self.item_id}
            )
        db_value = await self.compare_put_with_get(test_field, r)
        self.assertEqual(db_value, test_value)
        self.assert200(status)

    async def test_put_internal_skip_validation(self):
        # test that put_internal is available and working properly.
        test_field = "ref"
        test_value = "9876543210987654321098765"
        data = {test_field: test_value}
        async with self.app.test_request_context(self.item_id_url):
            r, _, _, status = await put_internal(
                self.known_resource,
                data,
                concurrency_check=False,
                skip_validation=True,
                **{"_id": self.item_id}
            )
        db_value = await self.compare_put_with_get(test_field, r)
        self.assertEqual(db_value, test_value)
        self.assert200(status)

    async def test_put_etag_header(self):
        # test that Etag is always includer with response header. See #562.
        changes = {"ref": "1234567890123456789012345"}
        headers = [("Content-Type", "application/json"), ("If-Match", self.item_etag)]
        r = await self.test_client.put(
            self.item_id_url, json=changes, headers=headers
        )
        self.assertTrue("Etag" in r.headers)

        # test that ETag is compliant to RFC 7232-2.3 and #794 is fixed.
        etag = r.headers["ETag"]

        self.assertTrue(etag[0] == '"')
        self.assertTrue(etag[-1] == '"')

    async def test_put_etag_header_enforce_ifmatch_disabled(self):
        self.app.config["ENFORCE_IF_MATCH"] = False
        changes = {"ref": "1234567890123456789012345"}
        headers = [("Content-Type", "application/json"), ("If-Match", self.item_etag)]
        r, status = await self.put(
            self.item_id_url, data=changes, headers=headers
        )
        self.assertTrue(ETAG in r)
        self.assertTrue(self.item_etag != r[ETAG])

    async def test_put_nested(self):
        changes = {
            "ref": "1234567890123456789012345",
            "location.city": "a nested city",
            "location.address": "a nested address",
        }
        r = await self.perform_put(changes)
        values = await self.compare_put_with_get("location", r)
        self.assertEqual(values["city"], "a nested city")
        self.assertEqual(values["address"], "a nested address")

    async def test_put_creates_unexisting_document(self):
        id = str(ObjectId())
        url = "%s/%s" % (self.known_resource_url, id)
        id_field = self.domain[self.known_resource]["id_field"]
        changes = {"ref": "1234567890123456789012345"}
        r, status = await self.put(url, data=changes)
        # 201 is a creation (POST) response
        self.assert201(status)
        # new document has id_field matching the PUT endpoint
        self.assertEqual(r[id_field], str(id))

    async def test_put_returns_404_on_unexisting_document(self):
        self.app.config["UPSERT_ON_PUT"] = False
        id = str(ObjectId())
        url = "%s/%s" % (self.known_resource_url, id)
        changes = {"ref": "1234567890123456789012345"}
        r, status = await self.put(url, data=changes)
        self.assert404(status)

    async def test_put_creates_unexisting_document_with_url_as_id(self):
        id = str(ObjectId())
        url = "%s/%s" % (self.known_resource_url, id)
        id_field = self.domain[self.known_resource]["id_field"]
        changes = {"ref": "1234567890123456789012345", id_field: str(ObjectId())}
        r, status = await self.put(url, data=changes)
        # 201 is a creation (POST) response
        self.assert201(status)
        # new document has id_field matching the PUT endpoint
        # (eventual mismatching id_field in the payload is ignored/replaced)
        self.assertEqual(r[id_field], str(id))

    async def test_put_creates_unexisting_document_fails_on_mismatching_id(self):
        id = str(ObjectId())
        id_field = self.domain[self.known_resource]["id_field"]
        changes = {"ref": "1234567890123456789012345", id_field: id}
        r, status = await self.put(
            self.item_id_url, data=changes, headers=[("If-Match", self.item_etag)]
        )
        self.assert400(status)
        self.assertTrue("immutable" in r["_error"]["message"])

    async def test_put_type_coercion(self):
        schema = self.domain[self.known_resource]["schema"]
        schema["aninteger"]["coerce"] = lambda string: int(float(string))
        changes = {"ref": "1234567890123456789054321", "aninteger": "42.3"}
        r, status = await self.put(
            self.item_id_url, data=changes, headers=[("If-Match", self.item_etag)]
        )
        self.assert200(status)
        r, status = await self.get(r["_links"]["self"]["href"])
        self.assertEqual(r["aninteger"], 42)

    async def perform_put(self, changes):
        r, status = await self.put(
            self.item_id_url, data=changes, headers=[("If-Match", self.item_etag)]
        )
        self.assert200(status)
        self.assertPutResponse(r, self.item_id)
        return r

    def assertPutResponse(self, response, item_id, resource=None):
        id_field = self.domain[resource or self.known_resource]["id_field"]
        self.assertTrue(STATUS in response)
        self.assertTrue(STATUS_OK in response[STATUS])
        self.assertFalse(ISSUES in response)
        self.assertTrue(id_field in response)
        self.assertEqual(response[id_field], item_id)
        self.assertTrue(LAST_UPDATED in response)
        self.assertTrue(ETAG in response)
        self.assertTrue("_links" in response)
        self.assertItemLink(response["_links"], item_id)

    async def compare_put_with_get(self, fields, put_response):
        raw_r = await self.test_client.get(self.item_id_url)
        r, status = await self.parse_response(raw_r)
        self.assert200(status)
        self.assertEqual(raw_r.headers.get("ETag").replace('"', ""), put_response[ETAG])
        if isinstance(fields, str):
            return r[fields]
        return [r[field] for field in fields]


class TestEvents(TestBase):
    new_ref = "0123456789012345678901234"

    async def test_on_pre_PUT(self):
        devent = DummyEventAsyncIO(self.before_replace)
        self.app.on_pre_PUT += devent
        await self.put()
        self.assertEqual(self.known_resource, devent.called[0])
        self.assertEqual(3, len(devent.called))

    async def test_on_pre_PUT_contacts(self):
        devent = DummyEventAsyncIO(self.before_replace)
        self.app.on_pre_PUT_contacts += devent
        await self.put()
        self.assertEqual(2, len(devent.called))

    async def test_on_pre_PUT_dynamic_filter(self):
        async def filter_this(resource, request, lookup):
            lookup["_id"] = self.unknown_item_id

        self.app.on_pre_PUT += filter_this
        # Would normally delete the known document; will return 404 instead.
        r, s = await self.parse_response(await self.put())
        self.assert201(s)

    async def test_on_post_PUT(self):
        devent = DummyEventAsyncIO(self.after_replace)
        self.app.on_post_PUT += devent
        await self.put()
        self.assertEqual(self.known_resource, devent.called[0])
        self.assertEqual(200, devent.called[2].status_code)
        self.assertEqual(3, len(devent.called))

    async def test_on_post_PUT_contacts(self):
        devent = DummyEventAsyncIO(self.after_replace)
        self.app.on_post_PUT_contacts += devent
        await self.put()
        self.assertEqual(200, devent.called[1].status_code)
        self.assertEqual(2, len(devent.called))

    async def test_on_replace(self):
        devent = DummyEventAsyncIO(self.before_replace)
        self.app.on_replace += devent
        await self.put()
        self.assertEqual(self.known_resource, devent.called[0])
        self.assertEqual(self.new_ref, devent.called[1]["ref"])
        self.assertEqual(3, len(devent.called))

    async def test_on_replace_contacts(self):
        devent = DummyEventAsyncIO(self.before_replace)
        self.app.on_replace_contacts += devent
        await self.put()
        self.assertEqual(self.new_ref, devent.called[0]["ref"])
        self.assertEqual(2, len(devent.called))

    async def test_on_replaced(self):
        devent = DummyEventAsyncIO(self.after_replace)
        self.app.on_replaced += devent
        await self.put()
        self.assertEqual(self.known_resource, devent.called[0])
        self.assertEqual(self.new_ref, devent.called[1]["ref"])
        self.assertEqual(3, len(devent.called))

    async def test_on_replaced_contacts(self):
        devent = DummyEventAsyncIO(self.after_replace)
        self.app.on_replaced_contacts += devent
        await self.put()
        self.assertEqual(self.new_ref, devent.called[0]["ref"])
        self.assertEqual(2, len(devent.called))

    async def before_replace(self):
        db = self.connection[MONGO_DBNAME]
        contact = await db.contacts.find_one(ObjectId(self.item_id))
        return contact["ref"] == self.item_name

    async def after_replace(self):
        return not await self.before_replace()

    def put(self):
        headers = [("Content-Type", "application/json"), ("If-Match", self.item_etag)]
        data = {"ref": self.new_ref}
        return self.test_client.put(self.item_id_url, json=data, headers=headers)
