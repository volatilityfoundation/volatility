from volatility.renderers.basic import Renderer, Bytes
from volatility import debug
import sqlite3

__author__ = 'mike'

class SqliteRenderer(Renderer):

    def __init__(self, plugin_name, config):
        self._plugin_name = plugin_name
        self._config = config
        self._db = None

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

    def _add_row(self, node, accumulator):
        accumulator[node] = max(accumulator.values()) + 1
        insert = "INSERT INTO " + self._plugin_name + " VALUES (?, ?, " + ", ".join(["?"] * len(node.values)) + ")"
        print insert, [accumulator[node], accumulator[node.parent]] + list(node.values)
        self._db.execute(insert, [accumulator[node], accumulator[node.parent]] + [str(v) for v in node.values])
        return accumulator

    def render(self, outfd, grid):
        """Renders the TreeGrid in data out to the output file from the config options"""
        if not self._config.OUTPUT_FILE:
            debug.error("Please specify a valid output file using --output-file")

        self._db = sqlite3.connect(self._config.OUTPUT_FILE, isolation_level = None)
        create = "CREATE TABLE IF NOT EXISTS " + self._plugin_name + "( id INTEGER, rowparent INTEGER, " + \
                 ", ".join(['"' + self._sanitize_name(i.name) + '" ' + self._column_type(i.type) for i in grid.columns]) + ")"
        self._db.execute(create)
        self._db.execute("BEGIN TRANSACTION")
        grid.visit(None, self._add_row, {None: 0})
        self._db.execute("COMMIT TRANSACTION")


class QuickSqliteRenderer(SqliteRenderer):
    def __init__(self, plugin_name, config):
        self._plugin_name = plugin_name
        self._config = config
        self._db = None
        self._accumulator = [0,[]]
        
    def render(self, outfd, grid):
        if not self._config.OUTPUT_FILE:
            debug.error("Please specify a valid output file using --output-file")

        self._db = sqlite3.connect(self._config.OUTPUT_FILE, isolation_level = None)
        create = "CREATE TABLE IF NOT EXISTS " + self._plugin_name + "( id INTEGER, " + \
                 ", ".join(['"' + self._sanitize_name(i.name) + '" ' + self._column_type(i.type) for i in grid.columns]) + ")"
        self._db.execute(create)

        def _add_multiple_row(node, accumulator):
            accumulator[0] = accumulator[0] + 1 #id
            accumulator[1].append([accumulator[0]] + [str(v) for v in node.values])
            if len(accumulator[1]) > 20000:
                self._db.execute("BEGIN TRANSACTION")
                insert = "INSERT INTO " + self._plugin_name + " VALUES (?, " + ", ".join(["?"] * len(node.values)) + ")"
                self._db.executemany(insert, accumulator[1])
                accumulator = [accumulator[0], []]
                self._db.execute("COMMIT TRANSACTION")
            self._accumulator = accumulator
            return accumulator            

        grid.populate(_add_multiple_row, self._accumulator)
        
        #Insert last nodes
        if len(self._accumulator[1]) > 0:
            self._db.execute("BEGIN TRANSACTION")
            insert = "INSERT INTO " + self._plugin_name + " VALUES (?, " + ", ".join(["?"] * (len(self._accumulator[1][0])-1)) + ")"
            self._db.executemany(insert, self._accumulator[1])
            self._db.execute("COMMIT TRANSACTION")    