import asyncio
import logging

import aiopg
import psycopg2
from psycopg2.extras import RealDictCursor


LATEST_BLOCK_NUM = """
SELECT max(block_num) FROM blocks
"""
LOGGER = logging.getLogger(__name__)

class Database(object):
    """Manages connection to the postgres database and makes async queries
    """
    def __init__(self, host, port, name, user, password, loop):
        self._dsn = 'dbname={} user={} password={} host={} port={}'.format(
            name, user, password, host, port)
        self._loop = loop
        self._conn = None

    async def connect(self, retries=5, initial_delay=1, backoff=2):
        """Initializes a connection to the database

        Args:
            retries (int): Number of times to retry the connection
            initial_delay (int): Number of seconds wait between reconnects
            backoff (int): Multiplies the delay after each retry
        """
        LOGGER.info('Connecting to database')

        delay = initial_delay
        for attempt in range(retries):
            try:
                self._conn = await aiopg.connect(
                    dsn=self._dsn, loop=self._loop, echo=True)
                LOGGER.info('Successfully connected to database')

                await self.init_auth_table()
                return

            except psycopg2.OperationalError:
                LOGGER.debug(
                    'Connection failed.'
                    ' Retrying connection (%s retries remaining)',
                    retries - attempt)
                await asyncio.sleep(delay)
                delay *= backoff

        self._conn = await aiopg.connect(
            dsn=self._dsn, loop=self._loop, echo=True)
        LOGGER.info('Successfully connected to database')

    def disconnect(self):
        """Closes connection to the database
        """
        self._conn.close()


    async def init_auth_table(self):
        create = """
        CREATE TABLE AUTH (
            NAME VARCHAR(25) NOT NULL,
            HASHED_PASSWORD VARCHAR(256) NOT NULL,
            PUBLIC_KEY VARCHAR(256) NOT NULL,
            ENCRYPTED_PRIVATE_KEY VARCHAR(256) NOT NULL,
            ROLE VARCHAR(25) NOT NULL 
        );
        """
        async with self._conn.cursor() as cursor:
            await cursor.execute(create)

        self._conn.commit()

    
    async def create_auth_entry(self,
    	                        name,
    	                        hashed_password,
                                public_key,
                                encrypted_private_key,
                                role):
        insert = """
        INSERT INTO AUTH (
            NAME,
            HASHED_PASSWORD,
            PUBLIC_KEY,
            ENCRYPTED_PRIVATE_KEY,
            ROLE
        )
        VALUES ('{}', '{}', '{}', '{}','{}');
        """.format(
            name,
            hashed_password.hex(),
            public_key,
            encrypted_private_key.hex(),
            role)

        async with self._conn.cursor() as cursor:
            await cursor.execute(insert)

        self._conn.commit()

        await self.create_name_table_entry(name)


    async def create_name_table_entry(self, name):
        create = """
        CREATE TABLE {} (
            REQUIRED_FIELDS VARCHAR(25) );
        """.format(name)

        async with self._conn.cursor() as cursor:
            await cursor.execute(create)

        self._conn.commit()


    async def edit_fields_entry(self, name, add_fields=None, delete_fields=None):
        rows = await self.fetch_fields_resource_by_name(name)
        current_fields = []
        for row in rows:
            current_fields.append(row['require_fields'])
        current_fields_set = set(current_fields)
        add_fields_set = set(add_fields)
        add_fields_set.difference_update(current_fields_set)
        add_fields = list(add_fields_set)

        #_fields = '), ('.join(add_fields)
        insert = """
        INSERT INTO {} (
            REQUIRED_FIELDS
        )
        VALUES (
        """.format(name)
        for _ in range(len(add_fields)):
            insert = insert + """ '{}' ), ("""
        insert = insert[:-3]
        insert = insert + """;"""
        insert = insert.format(*add_fields)

        async with self._conn.cursor() as cursor:
            await cursor.execute(insert)

        self._conn.commit()
        

    async def fetch_auth_resource_by_name(self, name):
        fetch = """
        SELECT * FROM AUTH WHERE NAME='{}'
        """.format(name)

        async with self._conn.cursor(cursor_factory=RealDictCursor) as cursor:
            await cursor.execute(fetch)
            return await cursor.fetchone()

    async def fetch_auth_resource_by_public_key(self, public_key):
        fetch = """
        SELECT * FROM AUTH WHERE PUBLIC_KEY='{}'
        """.format(public_key)

        async with self._conn.cursor(cursor_factory=RealDictCursor) as cursor:
            await cursor.execute(fetch)
            return await cursor.fetchone()

    async def fetch_fields_resource_by_name(self, name):
        fetch = """
        SELECT REQUIRED_FIELDS FROM {}
        """.format(name)

        async with self._conn.cursor(cursor_factory=RealDictCursor) as cursor:
            await cursor.execute(fetch)
            return await cursor.fetchall()