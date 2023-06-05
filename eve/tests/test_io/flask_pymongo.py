from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import OperationFailure

from eve.io.mongo.flask_pymongo import PyMongo
from eve.tests import TestBase
from eve.tests.test_settings import (MONGO1_DBNAME, MONGO1_PASSWORD,
                                     MONGO1_USERNAME, MONGO_HOST, MONGO_PORT)


class TestPyMongo(TestBase):
    async def asyncSetUp(self, url_converters=None):
        await super().asyncSetUp(url_converters)
        await self._setupdb()
        schema = {"title": {"type": "string"}}
        settings = {"schema": schema, "mongo_prefix": "MONGO1"}

        await self.app.register_resource("works", settings)

    async def test_auth_params_provided_in_mongo_url(self):
        self.app.config["MONGO1_URL"] = "mongodb://%s:%s@%s:%s" % (
            MONGO1_USERNAME,
            MONGO1_PASSWORD,
            MONGO_HOST,
            MONGO_PORT,
        )
        async with self.app.app_context():
            db = PyMongo(self.app, "MONGO1").db
        self.assertEqual(0, await db.works.count_documents({}))

    async def test_auth_params_provided_in_config(self):
        self.app.config["MONGO1_USERNAME"] = MONGO1_USERNAME
        self.app.config["MONGO1_PASSWORD"] = MONGO1_PASSWORD
        async with self.app.app_context():
            db = PyMongo(self.app, "MONGO1").db
        self.assertEqual(0, await db.works.count_documents({}))

    async def test_invalid_auth_params_provided(self):
        # if bad username and/or password is provided in MONGO_URL and mongo
        # run w\o --auth pymongo won't raise exception
        async def func():
            async with self.app.app_context():
                db = PyMongo(self.app, "MONGO1").db
                await db.works.find_one()

        self.app.config["MONGO1_USERNAME"] = "bad_username"
        self.app.config["MONGO1_PASSWORD"] = "bad_password"
        with self.assertRaises(OperationFailure):
            await func()

    async def test_invalid_port(self):
        self.app.config["MONGO1_PORT"] = "bad_value"
        with self.assertRaises(TypeError):
            await self._pymongo_instance()

    async def test_invalid_options(self):
        self.app.config["MONGO1_OPTIONS"] = {"connectTimeoutMS": "bad_value"}
        with self.assertRaises(ValueError):
            await self._pymongo_instance()

    async def test_valid_port(self):
        self.app.config["MONGO1_PORT"] = 27017
        async with self.app.app_context():
            db = PyMongo(self.app, "MONGO1").db
        self.assertEqual(0, await db.works.count_documents({}))

    async def _setupdb(self):
        self.connection = AsyncIOMotorClient()
        await self.connection.drop_database(MONGO1_DBNAME)
        db = self.connection[MONGO1_DBNAME]
        try:
            await db.command("dropUser", MONGO1_USERNAME)
        except OperationFailure:
            pass
        await db.command(
            "createUser", MONGO1_USERNAME, pwd=MONGO1_PASSWORD, roles=["dbAdmin"]
        )

    async def _pymongo_instance(self):
        async with self.app.app_context():
            PyMongo(self.app, "MONGO1")
