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
import os
import sqlite3
import binascii

import sys
sys.path.extend(["../../"])
from bbc1.core import logger

DIR_APP_SUPPORT = '.bbc1_app_support/'


def get_support_dir(domain_id):
    """Gets support directory path and if support directory does not exists the directory is made.

    Args:
        domain_id (str):

    Return:
        s_dir (str):

    """
    s_domain_id = binascii.b2a_hex(domain_id).decode()
    s_dir = DIR_APP_SUPPORT + s_domain_id + '/'
    if not os.path.exists(s_dir):
        os.makedirs(s_dir, mode=0o777, exist_ok=True)
    return s_dir


class Constants:

    MAX_INT8  = 0x7f
    MAX_INT16 = 0x7fff
    MAX_INT32 = 0x7fffffff
    MAX_INT64 = 0x7fffffffffffffff

    O_BIT_NONE = 0


class Database:

    def __init__(self, dbtype="sqlite", loglevel="all", logname=None):
        self.logger = logger.get_logger(key="app_support_db", level=loglevel,
                                        logname=logname)
        self.dbtype = dbtype
        self.db_name = dict()
        self.db = dict()
        self.db_cur = dict()


    def check_table_existence(self, domain_id, dbname, name):
        """Checks the table existence and if the table name does not exists in db, nothing will returns

        Args:
            domain_id (bytes):
            dbname (str): name of database
            name (str): name of table
        
        Return:
            ret (list):

        """
        ret = self.exec_sql_fetchone(domain_id, dbname,
            "select * from sqlite_master where type='table' and name=?", name)
        return ret


    def close_db(self, domain_id, dbname):
        """Closes the connection of database

        Args:
            domain_id (bytes):
            dbname (str):

        """
        if domain_id not in self.db or domain_id not in self.db_cur:
            return
        self.db_cur[domain_id][dbname].close()
        self.db[domain_id][dbname].close()


    def create_table_in_db(self, domain_id, dbname, tbl, tbl_definition,
                            primary_key=None, indices=[]):
        """Creates a table in the database and if domain_id is not registered to db or db_cur, nothing will returns 

        Args:
            domain_id (bytes):
            dbname (str): name of database
            tbl (str): name of table
            tbl_definition (list): ex) [["user_id", "BLOB"], ["public_key", "BLOB"], ["tx_id_added", "BLOB"], ["tx_id_removed", "BLOB"],]

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
        """Excecutes sql to the database

        Args:
            domain_id (bytes):
            dbname (str): name of database
            sql (str): query
            dat (str): variable for query, it could be tuple too
        
        Return:
            ret (list):

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
        """Excequtes sql and returns a single sequence

        Args:
            domain_id (bytes):
            dbname (str):
            sql (str):
            dat (str): variable for query, it could be tuple too
        
        Return:
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
        """Connects the database file. If the database file does not exist, it is created.
        
        dbname is must be set in the dbname dictionary in this class prior to calling this function.

        Args:
            domain_id (bytes):
            dbname (str):

        """
        if domain_id not in self.db or domain_id not in self.db_cur:
            return
        self.db[domain_id][dbname] = sqlite3.connect(
                        self.db_name[domain_id][dbname], isolation_level=None)
        self.db_cur[domain_id][dbname] = self.db[domain_id][dbname].cursor()


    def setup_db(self, domain_id, name):
        """Setup the database and create the directory named as domain_id under ".bbc1_app_supports/"

        Args:
            domain_id (bytes): 
            name (str): name of database

        """
        self.db_name[domain_id] = dict()
        s_dir = get_support_dir(domain_id)
        self.db_name[domain_id][name] = s_dir + name + '.sqlite3'
        self.db[domain_id] = dict()
        self.db_cur[domain_id] = dict()


# end of app_db_lib.py
