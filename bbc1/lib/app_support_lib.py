# -*- coding: utf-8 -*-
"""
Copyright (c) 2018 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import binascii
import hashlib
import os
import sqlite3

import sys
sys.path.extend(["../../"])

from bbc1.core import bbclib, logger


DIR_APP_SUPPORT = '.bbc1_app_support'


def get_support_dir(domain_id):
    """Gets application support directory path.

    If the directory does not exist, then the directory is created.

    Args:
        domain_id (bytes): The application domain.

    Returns:
        s_dir (str): The relative path of the application support directory.

    """
    s_domain_id = binascii.b2a_hex(domain_id).decode()
    s_dir = os.environ.get('BBC1_APP_SUPPORT_DIR', DIR_APP_SUPPORT) + '/' \
            + s_domain_id + '/'
    if not os.path.exists(s_dir):
        os.makedirs(s_dir, mode=0o777, exist_ok=True)
    return s_dir


def get_timestamp_in_seconds(transaction):
    """Gets timestamp of a transaction in seconds.

    A BBcTransaction object (since core v1.3) stores the timestamp in
    milliseconds. This function is provided for those application who wants
    to deal with timestamps in seconds.

    Args:
        transaction (BBcTransaction): The transaction to get the timestamp of.

    Returns:
        timestamp (int): The timestamp (UNIX time) in seconds.

    """
    return transaction.timestamp // 1000


class Constants:

    """Collection of constants to be used in the library or application.

    Common constants are provided. Libraries or applications should derive
    their own constant classes from this.
    """

    MAX_INT8  = 0x7f
    MAX_INT16 = 0x7fff
    MAX_INT32 = 0x7fffffff
    MAX_INT64 = 0x7fffffffffffffff

    O_BIT_NONE = 0


class Database:

    """Common database object.

    Currently supports SQLite only.
    """

    def __init__(self, dbtype="sqlite", loglevel="all", logname=None):
        """Initializes the object.

        Args:
            dbtype (str): The type of database. "sqlite" by default.
            loglevel (str): The logging level. "all" by default.
            logname (str): The logger name. None by default.

        """
        self.logger = logger.get_logger(key="app_support_db", level=loglevel,
                                        logname=logname)
        self.dbtype = dbtype
        self.db_name = dict()
        self.db = dict()
        self.db_cur = dict()


    def check_table_existence(self, domain_id, dbname, name):
        """Checks the existence of a table.

        Args:
            domain_id (bytes): The application domain.
            dbname (str): The name of the database.
            name (str): The name of the table to check the existence.
        
        Returns:
            ret (list): The SQL result. None if the table does not exist.

        """
        ret = self.exec_sql_fetchone(domain_id, dbname,
            "select * from sqlite_master where type='table' and name=?", name)
        return ret


    def close_db(self, domain_id, dbname):
        """Closes the connection to the database.

        Args:
            domain_id (bytes): The application domain.
            dbname (str): The name of the database to close the connection to.

        """
        if domain_id not in self.db or domain_id not in self.db_cur:
            return
        self.db_cur[domain_id][dbname].close()
        self.db[domain_id][dbname].close()


    def create_table_in_db(self, domain_id, dbname, tbl, tbl_definition,
                            primary_key=None, indices=[]):
        """Creates a table in the specified database.

        Args:
            domain_id (bytes): The application domain.
            dbname (str): The name of the database.
            tbl (str): The name of the table to create.
            tbl_definition (list): The definition of the table in a list.
            primary_key (int): The index of the primary key. None by default.
            indices (array): The indices of the indices. [] by default.

        """
        if domain_id not in self.db or domain_id not in self.db_cur or \
          domain_id not in self.db_name:
            return
        if self.check_table_existence(domain_id, dbname, tbl) is not None:
            return
        sql = "CREATE TABLE %s " % tbl
        sql += "("
        sql += ", ".join(["%s %s" % (d[0],d[1]) for d in tbl_definition])
        if primary_key is not None:
            sql += ", PRIMARY KEY ("+tbl_definition[primary_key][0]+")"
        sql += ");"
        self.exec_sql(domain_id, dbname, sql)
        for idx in indices:
            self.exec_sql(domain_id, dbname,
                        "CREATE INDEX %s_idx_%d ON %s (%s);" %
                        (tbl, idx, tbl, tbl_definition[idx][0]))


    def exec_sql(self, domain_id, dbname, sql, *dat):
        """Excecutes an SQL statement for the specified database.

        Args:
            domain_id (bytes): The application domain.
            dbname (str): The name of the database.
            sql (str): The SQL statement to execute.
            dat (tuple): The replacement values for the statement.
        
        Returns:
            ret (list): The results.

        """
        if domain_id not in self.db or domain_id not in self.db_cur or \
          domain_id not in self.db_name:
            return None
        if dbname not in self.db[domain_id]:
            self.open_db(domain_id, dbname)
        if len(dat) > 0:
            ret = self.db_cur[domain_id][dbname].execute(sql, (*dat,))
        else:
            ret = self.db_cur[domain_id][dbname].execute(sql)
        if ret is not None:
            ret = list(ret)
        return ret


    def exec_sql_fetchone(self, domain_id, dbname, sql, *dat):
        """Excequtes an SQL statement to receive a single result.

        Args:
            domain_id (bytes): The application domain.
            dbname (str): The name of the database.
            sql (str): The SQL statement to execute.
            dat (tuple): The replacement values for the statement.
        
        Returns:
            ret (list):

        """
        if domain_id not in self.db or domain_id not in self.db_cur or \
          domain_id not in self.db_name:
            return None
        if dbname not in self.db[domain_id]:
            self.open_db(domain_id, dbname)
        if len(dat) > 0:
            ret = self.db_cur[domain_id][dbname].execute(
                    sql, (*dat,)).fetchone()
        else:
            ret = self.db_cur[domain_id][dbname].execute(sql).fetchone()
        if ret is not None:
            ret = list(ret)
        return ret


    def open_db(self, domain_id, dbname):
        """Connects to the specified database.

        If the database file does not exist, it is created.

        Args:
            domain_id (bytes): The application domain.
            dbname (str): The name of the database.

        """
        if domain_id not in self.db or domain_id not in self.db_cur:
            return
        self.db[domain_id][dbname] = sqlite3.connect(
                        self.db_name[domain_id][dbname], isolation_level=None)
        self.db_cur[domain_id][dbname] = self.db[domain_id][dbname].cursor()


    def setup_db(self, domain_id, name):
        """Sets up the database to reside in the application support directory.

        Args:
            domain_id (bytes): The appication domain.
            name (str): The name of database.

        """
        self.db_name[domain_id] = dict()
        s_dir = get_support_dir(domain_id)
        self.db_name[domain_id][name] = s_dir + name + '.sqlite3'
        self.db[domain_id] = dict()
        self.db_cur[domain_id] = dict()


class TransactionLabel:

    """Label of a transaction.

    Creates and interprets a BBcEvent object.
    """

    def __init__(self, label_group_id, label_id=None):
        """Initializes the object.

        Args:
            label_group_id (bytes): The ID of labels for an application.
            label_id (bytes): The digest of a label.

        """
        self.label_group_id = label_group_id
        self.label_id = label_id


    @staticmethod
    def create_label_id(label, salt):
        """Creates the digest of a label.

        Args:
            label (str): The label string.
            salt (str): A salt to prevent dictionary attacks.

        Returns:
            label_id (bytes): The digest of the label.

        """
        dat = bytearray(label.encode())
        dat.extend(salt.encode())
        return hashlib.sha256(bytes(dat)).digest()


    def get_event(self):
        """Gets the BBcEvent object for a label to embed in a transaction.

        Returns:
            event (BBcEvent): The event to embed in a transaction as a lebel.

        """
        event = bbclib.BBcEvent(asset_group_id=self.label_group_id)
        event.add(asset=bbclib.BBcAsset())
        event.asset.add(user_id=self.label_id)
        return event


    def get_label_id(self, tx):
        """Gets the label ID embedded in a transaction.

        Args:
            tx (BBcTransaction): The transaction.

        Returns:
            label_id (bytes): The label ID.

        """
        for event in tx.events:
            if event.asset_group_id == self.label_group_id:
                return event.asset.user_id

        return None


    def is_labeled(self, tx):
        """Checks if the label ID is embedded in a transaction.

        Args:
            tx (BBcTransaction): The transaction.

        Returns:
            labeled (bool): True if tx has the label ID

        """
        for event in tx.events:
            if event.asset_group_id == self.label_group_id:
                return event.asset.user_id == self.label_id

        return False


# end of app_support_lib.py
