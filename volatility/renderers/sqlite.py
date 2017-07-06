# Volatility
# Copyright (C) 2008-2015 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

from volatility.renderers.basic import Renderer, Bytes
from volatility import debug
import sqlite3

class SqliteRenderer(Renderer):

    def __init__(self, plugin_name, config):
        self._plugin_name = plugin_name
        self._config = config
        self._db = None
        self._accumulator = [0,[]]

    column_types = [(str, "TEXT"),
                    (int, "TEXT"),
                    (float, "TEXT"),
                    (Bytes, "BLOB")]

    def _column_type(self, col_type):
        for (t, v) in self.column_types:
            if issubclass(col_type, t):
                return v
        return "TEXT"

    def _sanitize_name(self, name):
        return name

    def render(self, outfd, grid):
        if not self._config.OUTPUT_FILE:
            debug.error("Please specify a valid output file using --output-file")

        self._db = sqlite3.connect(self._config.OUTPUT_FILE, isolation_level = None)
        # Change text factory from unicode to bytestring to allow insertion of non-ASCII characters
        # Sometimes process remainders in memory cause funky names et.al. to be retrieved
        self._db.text_factory = str
        create = "CREATE TABLE IF NOT EXISTS " + self._plugin_name + "( id INTEGER, " + \
                 ", ".join(['"' + self._sanitize_name(i.name) + '" ' + self._column_type(i.type) for i in grid.columns]) + ")"
        self._db.execute(create)

        def _add_multiple_row(node, accumulator):
            accumulator[0] = accumulator[0] + 1 #id
            accumulator[1].append([accumulator[0]] + [str(v) for v in node.values])
            if len(accumulator[1]) > 20000:
                self._db.execute("BEGIN TRANSACTION")
                insert = "INSERT INTO " + self._plugin_name + " (id, " + \
                     ", ".join(['"' + self._sanitize_name(i.name) + '"' for i in grid.columns]) + ") " + \
                     " VALUES (?, " + ", ".join(["?"] * len(node.values)) + ")"
                self._db.executemany(insert, accumulator[1])
                accumulator = [accumulator[0], []]
                self._db.execute("COMMIT TRANSACTION")
            self._accumulator = accumulator
            return accumulator

        grid.populate(_add_multiple_row, self._accumulator)

        #Insert last nodes
        if len(self._accumulator[1]) > 0:
            self._db.execute("BEGIN TRANSACTION")
            insert = "INSERT INTO " + self._plugin_name + " (id, " + \
                     ", ".join(['"' + self._sanitize_name(i.name) + '"' for i in grid.columns]) + ") " + \
                     " VALUES (?, " + ", ".join(["?"] * (len(self._accumulator[1][0])-1)) + ")"
            self._db.executemany(insert, self._accumulator[1])
            self._db.execute("COMMIT TRANSACTION")  
