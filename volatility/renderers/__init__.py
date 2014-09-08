"""Renderers

Renderers display the unified output format in some manner (be it text or file or graphical output"""

import collections
from volatility import validity, fmtspec


class TreeRow(validity.ValidityRoutines):
    """Class providing the interface for an individual Row of the TreeGrid"""

    def __init__(self, treegrid, values):
        self.type_check(treegrid, TreeGrid)
        if not isinstance(self, TreeGrid):
            self.type_check(values, list)
            treegrid.validate_values(values)
        self._treegrid = treegrid
        self._children = []
        self._values = values

    def add_child(self, child):
        """Appends a child to the current Row"""
        self.type_check(child, TreeRow)
        self._children += [child]

    def insert_child(self, child, position):
        """Inserts a child at a specific position in the current Row"""
        self.type_check(child, TreeRow)
        self._children = self._children[:position] + [child] + self._children[:position]

    def clear(self):
        """Removes all children from this row

        :rtype : None
        """
        self._children = []

    @property
    def values(self):
        """The individual cell values of the row"""
        return self._values

    @property
    def children(self):
        """Returns an iterator of the children of the current row

        :rtype : iterator of TreeRows
        """
        for child in self._children:
            yield child

    def iterator(self, level = 0):
        """Returns an iterator of all rows with their depths

        :type level: int
        :param level: Indicates the depth of the current iterator
        """
        yield (level, self)
        for child in self.children:
            for grandchild in child.iterator(level + 1):
                yield grandchild


Column = collections.namedtuple('Column', ['index', 'name', 'type'])


class TreeGrid(TreeRow):
    """Class providing the interface for a TreeGrid (which contains TreeRows)"""

    simple_types = {int, str, float, bytes}

    def __init__(self, columns):
        """Constructs a TreeGrid object using a specific set of columns

        The TreeGrid itself is a root element, that can have children but no values.
        The TreeGrid does *not* contain any information about formatting,
        these are up to the renderers and plugins.

        :param columns: A list of column tuples made up of (name, type).
        """
        self.type_check(columns, list)
        converted_columns = []
        for (name, column_type) in columns:
            is_simple_type = False
            for stype in self.simple_types:
                is_simple_type = is_simple_type or issubclass(column_type, stype)
            if not is_simple_type:
                raise TypeError("Column " + name + "'s type " + column_type.__class__.__name__ +
                                " is not a simple type")
            converted_columns.append(Column(len(converted_columns), name, column_type))
        self._columns = converted_columns

        # We can use the special type None because we're the top level node without values
        TreeRow.__init__(self, self, None)

    @property
    def columns(self):
        """Returns list of tuples of (name, type and format_hint)"""
        for column in self._columns:
            yield column

    def validate_values(self, values):
        """Takes a list of values and verified them against the column types"""
        if len(values) != len(self._columns):
            raise ValueError("The length of the values provided does not match the number of columns.")
        for column in self._columns:
            if not isinstance(values[column.index], column.type):
                raise TypeError("Column type " + str(column.index) + " is incorrect.")

    def iterator(self, level = 0):
        """Returns an iterator of all rows with their depths

        :type level: int
        :param level: Indicates the depth of the current iterator
        """
        for child in self.children:
            for grandchild in child.iterator(level + 1):
                yield grandchild
