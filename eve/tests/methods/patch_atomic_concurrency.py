import sys

import simplejson as json

import eve.methods.common
from eve.tests import TestBase
from eve.utils import config

"""
Atomic Concurrency Checks

Prior to commit 54fd697 from 2016-November, ETags would be verified
twice during a patch. One ETag check would be non-atomic by Eve,
then again atomically by MongoDB during app.data.update(filter).
The atomic ETag check was removed during issue #920 in 54fd697

When running Eve in a scale-out environment (multiple processes),
concurrent simultaneous updates are sometimes allowed, because
the Python-only ETag check is not atomic.

There is a critical section in patch_internal() between get_document()
and app.data.update() where a competing Eve process can change the
document and ETag.

This test simulates another process changing data & ETag during
the critical section. The test patches get_document() to return an
intentionally wrong ETag.
"""


async def get_document_simulate_concurrent_update(*args, **kwargs):
    """
    Hostile version of get_document

    This simluates another process updating MongoDB (and ETag) in
    eve.methods.patch.patch_internal() during the critical area
    between get_document() and app.data.update()
    """
    document = await eve.methods.common.get_document(*args, **kwargs)
    document[config.ETAG] = "unexpected change!"
    return document


class TestPatchAtomicConcurrent(TestBase):
    async def asyncSetUp(self):
        """
        Patch eve.methods.patch.get_document with a hostile version
        that simulates simultaneous updates
        """
        self.original_get_document = sys.modules["eve.methods.patch"].get_document
        sys.modules[
            "eve.methods.patch"
        ].get_document = get_document_simulate_concurrent_update
        return await super().asyncSetUp()

    async def test_etag_changed_after_get_document(self):
        """
        Try to update a document after the ETag was adjusted
        outside this process
        """
        changes = {"ref": "1234567890123456789054321"}
        _r, status = await self.patch(
            self.item_id_url, data=changes, headers=[("If-Match", self.item_etag)]
        )
        self.assertEqual(status, 412)

    async def asyncTearDown(self):
        """Remove patch of eve.methods.patch.get_document"""
        sys.modules["eve.methods.patch"].get_document = self.original_get_document
        return await super().asyncTearDown()

    async def patch(self, url, data, headers=[]):
        headers.append(("Content-Type", "application/json"))
        r = await self.test_client.patch(url, json=data, headers=headers)
        return await self.parse_response(r)
