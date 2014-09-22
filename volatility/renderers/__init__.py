"""Renderers

Renderers display the unified output format in some manner (be it text or file or graphical output"""

import collections

Column = collections.namedtuple('Column', ['index', 'name', 'type'])

class TreeRow(object):
    def __init__(self, path, treegrid, parent, data):
        self._treegrid = treegrid
        self._parent = parent
        self._path = path
        # TODO: Validate data
        self._data = data

    def __repr__(self):
        return "<TreeRow [" + self._path + "] - " + repr(self._data) + ">"

    @property
    def data(self):
        return self._data

    @property
    def path(self):
        return self._path

    @property
    def parent(self):
        return self._parent

    @property
    def path_depth(self):
        return len(self.path.split(TreeGrid.path_sep))

    def path_changed(self, path, added = False):
        components = self._path.split(TreeGrid.path_sep)
        changed = path.split(TreeGrid.path_sep)
        changed_index = len(changed) - 1
        if int(components[changed_index]) >= int(changed[-1]):
            components[changed_index] = str(int(components[changed_index]) + (1 if added else -1))
        self._path = TreeGrid.path_sep.join(components)

class TreeGrid(object):
    """Class providing the interface for a TreeGrid (which contains TreeRows)"""

    simple_types = {int, str, float, bytes}
    path_sep = "|"

    def __init__(self, columns):
        """Constructs a TreeGrid object using a specific set of columns

        The TreeGrid itself is a root element, that can have children but no values.
        The TreeGrid does *not* contain any information about formatting,
        these are up to the renderers and plugins.

        :param columns: A list of column tuples made up of (name, type).
        """
        # TODO: Type check columns
        self._rows = []
        converted_columns = []
        if len(columns) < 1:
            raise ValueError("Columns must be a list containing at least one column")
        for (name, column_type) in columns:
            is_simple_type = False
            for stype in self.simple_types:
                is_simple_type = is_simple_type or issubclass(column_type, stype)
            if not is_simple_type:
                raise TypeError("Column " + name + "'s type " + column_type.__class__.__name__ +
                                " is not a simple type")
            converted_columns.append(Column(len(converted_columns), name, column_type))
        self._columns = converted_columns

    @property
    def columns(self):
        """Returns the available columns and their ordering and types"""
        return self._columns

    def _find_rows(self, node):
        """Returns the rows list associated with a particular node

           Returns None if the node does not exist
        """
        rows = self._rows
        try:
            if node is not None:
                for path_component in node.path.split(self.path_sep):
                    _, rows = rows[int(path_component)]
        except IndexError:
            return None
        return rows

    def values(self, node):
        """Returns the values for the row"""
        rows = self._rows
        if node is None:
            raise ValueError("Node must be a valid node within the TreeGrid")
        try:
            for path_component in node.path.split(self.path_sep):
                node, rows = rows[int(path_component)]
        except IndexError:
            return None
        return node.data

    def _validate_row(self, row):
        if not (isinstance(row, list) and len(row) == len(self.columns)):
            raise TypeError("Row must be a list of objects made up of simple types and number the same as the columns")
        for index in range(len(self.columns)):
            column = self.columns[index]
            if not isinstance(row[index], column.type):
                raise TypeError("Row item with index " + repr(index) + " is the wrong type for column " + repr(column.name))


    def append(self, parent, row = None):
        """Adds a new row at the top level if parent is None, or under the parent row

           The row values will be empty until the values are set using .set or .set_value
        """
        rows = self._find_rows(parent)
        if rows is None:
            rows = []
        return self.insert(parent, len(rows), row)

    def clear(self):
        """Clears all rows from the TreeModel"""
        self._rows = []

    def insert(self, parent, position, row = None):
        """Inserts an element into the tree at a specific position"""
        parent_path = ""
        rows = self._find_rows(parent)
        if parent is not None:
            parent_path = parent.path + self.path_sep
        if rows is None:
            raise IndexError("Invalid parent node")
        newpath = parent_path + str(position)
        self._validate_row(row)
        tree_item = TreeRow(newpath, self, parent, row)
        for node, _ in rows[position:]:
            self.visit(node, lambda child, _: child.path_changed(newpath, True))
        rows.insert(position, (tree_item, []))
        return tree_item

    def _insert_sibling(self, parent, sibling, row = None, before = True):
        """Inserts an element into the tree, after the sibling.

        If parent is None, then the sibling must be in the top level
        If sibling is None, then the row will be inserted at the end of the parent's children
        """
        # Get the parent sorted out first
        if sibling is not None:
            if parent is None:
                parent = sibling.parent
            else:
                if sibling.parent is not parent:
                    raise ValueError("Sibling's parent is not parent")

        rows = self._rows
        if parent is not None:
            rows = self._find_rows(parent)
            if rows is None:
                raise ValueError("Invalid parent node")

        if sibling is None:
            i = 0 if before else len(rows)

        for i in range(len(rows)):
            testnode, _ = rows[i]
            if testnode == sibling:
                if not before:
                    i = i+1
                break
        else:
            raise ValueError("Sibling is not in parent's children")
        return self.insert(parent, i, row)


    def insert_after(self, parent, sibling, row = None):
        return self._insert_sibling(parent, sibling, row, False)

    def insert_before(self, parent, sibling, row = None):
        return self._insert_sibling(parent, sibling, row, True)

    def is_ancestor(self, node, descendant):
        """Returns true if descendent is a child, grandchild, etc of node"""
        return descendant.path.startswith(node.path)

    def path_depth(self, node):
        return node.path_depth

    def path_is_valid(self, node):
        """Returns True is a given path is valid for this treegrid"""
        return node in self._find_rows(node.parent)

    def prepend(self, parent, row = None):
        return self.insert(parent, 0, row)

    def remove(self, node):
        rows = self._find_rows(node.parent)
        if rows is None or len(rows) < 1:
            raise ValueError("Invalid node or node parent")
        deletion = None
        i = 0
        for i in range(len(rows)):
            potential_node, subrows = rows[i]
            if potential_node == node:
                deletion = i
            if deletion is not None:
                self.visit(potential_node, lambda grandchild, _: grandchild.path_changed(node.path, False))
        if deletion is None:
            raise ValueError("Invalid node path")
        del rows[deletion]

    def visit(self, node, function, initial_accumulator = None):
        """Visits all the nodes in a tree, calling function on each one"""
        # Find_rows is path dependent, whereas _visit is not
        # So in case the function modifies the node's path, find the rows first
        rows = self._find_rows(node)
        accumulator = function(node, initial_accumulator)
        if rows is not None:
            accumulator = self._visit(rows, function, accumulator)
        return accumulator

    def _visit(self, list_of_children, function, accumulator):
        """Visits all the nodes in a tree, calling function on each one"""
        if list_of_children is not None:
            for n, children in list_of_children:
                accumulator = function(n, accumulator)
                accumulator = self._visit(children, function, accumulator)
        return accumulator

def pretty_print(node, _accumulator):
    if node is not None:
        print "  " * node.path_depth, node._data, node.path

def build_example_treegrid():
    tg = TreeGrid([("Offset (V)", int), ("Offset (P)", int)])
    row = tg.append(None, [100, 200])
    three = tg.append(row, [200, 300])
    two = tg.append(None, [110, 210])
    tg.append(two, [210, 310])
    four = tg.insert_before(None, two, [105, 205])
    tg.insert_after(None, four, [106, 206])
    tg.prepend(three, [300, 400])
    five = tg.prepend(row, [199, 299])
    # tg.remove(five)
    return tg

if __name__ == '__main__':
    tg = build_example_treegrid()
    tg.visit(None, pretty_print)
