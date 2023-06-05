"""
    eve.io.mongo.media
    ~~~~~~~~~~~~~~~~~~

    GridFS media storage for Eve-powered APIs.

    :copyright: (c) 2017 by Nicola Iarocci.
    :license: BSD, see LICENSE for more details.
"""
from bson import ObjectId
from quart import Quart
from motor.motor_asyncio import AsyncIOMotorGridFSBucket

from eve.io.media import MediaStorage
from eve.io.mongo import Mongo
from eve.utils import str_type


class GridFSMediaStorage(MediaStorage):
    """The GridFSMediaStorage class stores files into GridFS.

    ..versionadded:: 0.3
    """

    def __init__(self, app=None):
        """
        :param app: the flask application (eve itself). This can be used by
        the class to access, amongst other things, the app.config object to
        retrieve class-specific settings.

        .. versionchanged:: 0.6
           Support for multiple, cached, GridFS instances
        """
        super().__init__(app)

        self.validate()
        self._fs = {}

    def validate(self):
        """Make sure that the application data layer is a eve.io.mongo.Mongo
        instance.
        """
        if self.app is None:
            raise TypeError("Application object cannot be None")

        if not isinstance(self.app, Quart):
            raise TypeError("Application object must be a Eve application")

    def fs(self, resource=None):
        """Provides the instance-level GridFS instance, instantiating it if
        needed.

        .. versionchanged:: 0.6
           Support for multiple, cached, GridFS instances
        """
        driver = self.app.data
        if driver is None or not isinstance(driver, Mongo):
            raise TypeError("Application data object must be of eve.io.Mongo " "type.")

        px = driver.current_mongo_prefix(resource)
        if px not in self._fs:
            self._fs[px] = AsyncIOMotorGridFSBucket(driver.pymongo(prefix=px).db)
        return self._fs[px]

    async def get(self, _id, resource=None):
        """Returns the file given by unique id. Returns None if no file was
        found.

        .. versionchanged: 0.6
           Support for _id as string.
        """
        if isinstance(_id, str_type):
            # Convert to unicode because ObjectId() interprets 12-character
            # strings (but not unicode) as binary representations of ObjectId.
            try:
                _id = ObjectId(unicode(_id))
            except NameError:
                _id = ObjectId(_id)

        _file = None
        try:
            _file = await self.fs(resource).open_download_stream(_id)
        except Exception:
            pass
        return _file

    async def put(self, content, filename=None, content_type=None, resource=None):
        """Saves a new file in GridFS. Returns the unique id of the stored
        file. Also stores content type of the file.
        """
        if hasattr(content, "stream") and hasattr(content.stream, "seek"):
            content.stream.seek(0)
        return await self.fs(resource).upload_from_stream(
            filename=filename,
            source=content,
            metadata={"contentType": content_type}
        )

    async def delete(self, _id, resource=None):
        """Deletes the file referenced by unique id."""
        await self.fs(resource).delete(_id)

    async def exists(self, id_or_document, resource=None):
        """Returns True if a file referenced by the unique id or the query
        document already exists, False otherwise.

        Valid query: {'filename': 'file.txt'}
        """
        return len(await self.fs(resource).find({"_id": id_or_document}).limit(1).to_list(None))
