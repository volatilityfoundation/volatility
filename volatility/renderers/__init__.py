"""Renderers

Renderers display the unified output format in some manner (be it text or file or graphical output"""

import collections

Column = collections.namedtuple('Column', ['index', 'name', 'type'])

class TreeNode(collections.Sequence):
    """Class representing a particular node in a tree grid"""
    def __init__(self, path, treegrid, parent, values):
        if not isinstance(treegrid, TreeGrid):
            raise TypeError("Treegrid must be an instance of TreeGrid")
        self._treegrid = treegrid
        self._parent = parent
        self._path = path
        self._validate_values(values)
        self._values = treegrid.RowTuple(*values)

    def __repr__(self):
        return "<TreeNode [" + self._path + "] - " + repr(self._values) + ">"

    def __getitem__(self, item):
        return self._treegrid.children(self).__getitem__(item)

    def __len__(self):
        return len(self._treegrid.children(self))

    def _validate_values(self, values):
        """A function for raising exceptions if a given set of values is invalid according to the column properties."""
        if not (isinstance(values, list) and len(values) == len(self._treegrid.columns)):
            raise TypeError(
                "Values must be a list of objects made up of simple types and number the same as the columns")
        for index in range(len(self._treegrid.columns)):
            column = self._treegrid.columns[index]
            if not isinstance(values[index], column.type):
                raise TypeError(
                    "Values item with index " + repr(index) + " is the wrong type for column " + repr(column.name))

    @property
    def values(self):
        """Returns the list of values from the particular node, based on column.index"""
        return self._values

    @property
    def path(self):
        """Returns a path identifying string

        This should be seen as opaque by external classes,
        Parsing of path locations based on this string are not guaranteed to remain stable.
        """
        return self._path

    @property
    def parent(self):
        """Returns the parent node of this node or None"""
        return self._parent

    @property
    def path_depth(self):
        """Return the path depth of the current node"""
        return len(self.path.split(TreeGrid.path_sep))

    def path_changed(self, path, added = False):
        """Updates the path based on the addition or removal of a node higher up in the tree

           This should only be called by the containing TreeGrid and expects to only be called for affected nodes.
        """
        components = self._path.split(TreeGrid.path_sep)
        changed = path.split(TreeGrid.path_sep)
        changed_index = len(changed) - 1
        if int(components[changed_index]) >= int(changed[-1]):
            components[changed_index] = str(int(components[changed_index]) + (1 if added else -1))
        self._path = TreeGrid.path_sep.join(components)

class TreeGrid(object):
    """Class providing the interface for a TreeGrid (which contains TreeNodes)

    The structure of a TreeGrid is designed to maintain the structure of the tree in the single object.
    For this reason each TreeNode does not hold its children, they are managed by the top level object.
    This leaves the Nodes as simple data carries and prevents them being used to manipulate the tree as a whole.
    This is a data structure, and is not expected to be modified much once created.

    There is no easy way to maintain a simple parent link from the child, if children are carried out in the structure
    of the parent itself.
    """

    simple_types = {int, long, str, float, bytes}
    path_sep = "|"

    def __init__(self, columns):
        """Constructs a TreeGrid object using a specific set of columns

        The TreeGrid itself is a root element, that can have children but no values.
        The TreeGrid does *not* contain any information about formatting,
        these are up to the renderers and plugins.

        :param columns: A list of column tuples made up of (name, type).
        """
        self._children = []
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
        self.RowTuple = collections.namedtuple("RowTuple", [self._sanitize(column.name) for column in converted_columns])
        self._columns = converted_columns

    def _sanitize(self, text):
        output = ""
        for letter in text.lower():
            if letter != ' ':
                output += (letter if letter in 'abcdefghiljklmnopqrstuvwxyz_' else '_')
        return output

    @property
    def columns(self):
        """Returns the available columns and their ordering and types"""
        return self._columns

    def children(self, node):
        """Returns the subnodes of a particular node in order"""
        return [node for node, _ in self._find_children(node)]

    def _find_children(self, node):
        """Returns the children list associated with a particular node

           Returns None if the node does not exist
        """
        children = self._children
        try:
            if node is not None:
                for path_component in node.path.split(self.path_sep):
                    _, children = children[int(path_component)]
        except IndexError:
            return []
        return children

    def values(self, node):
        """Returns the values for a particular node

           The values returned are mutable,
        """
        if node is None:
            raise ValueError("Node must be a valid node within the TreeGrid")
        return node.values

    def append(self, parent, values):
        """Adds a new node at the top level if parent is None, or under the parent node otherwise, after all other children."""
        children = self.children(parent)
        return self.insert(parent, len(children), values)

    def clear(self):
        """Clears all nodes from the TreeGrid"""
        self._children = []

    def insert(self, parent, position, values):
        """Inserts an element into the tree at a specific position"""
        parent_path = ""
        children = self._find_children(parent)
        if parent is not None:
            parent_path = parent.path + self.path_sep
        newpath = parent_path + str(position)
        tree_item = TreeNode(newpath, self, parent, values)
        for node, _ in children[position:]:
            self.visit(node, lambda child, _: child.path_changed(newpath, True))
        children.insert(position, (tree_item, []))
        return tree_item

    def _insert_sibling(self, parent, sibling, values, before = True):
        """Inserts an element into the tree, after the sibling.

        If parent is None, then the sibling must be in the top level
        If sibling is None, then the node will be inserted at the start/end of the parent's children depending on before
        """
        # Get the parent sorted out first
        if sibling is not None:
            if parent is None:
                parent = sibling.parent
            else:
                if sibling.parent is not parent:
                    raise ValueError("Sibling's parent is not parent")

        children = [node for node, _ in self._children]
        if parent is not None:
            children = self.children(parent)

        if sibling is None:
            i = 0 if before else len(children)

        for i in range(len(children)):
            if children[i] == sibling:
                if not before:
                    i = i+1
                break
        else:
            raise ValueError("Sibling is not in parent's children")
        return self.insert(parent, i, values)


    def insert_after(self, parent, sibling, values):
        """Insert a new node (with values) after the sibling node under parent

        If parent is None, then the sibling must be in the top level
        If sibling is None, then the node will be inserted at the start/end of the parent's children depending on before
        """
        return self._insert_sibling(parent, sibling, values, False)

    def insert_before(self, parent, sibling, values):
        """Insert a new node (with values) before the sibling node under parent

        If parent is None, then the sibling must be in the top level
        If sibling is None, then the node will be inserted at the start/end of the parent's children depending on before
        """
        return self._insert_sibling(parent, sibling, values, True)

    def is_ancestor(self, node, descendant):
        """Returns true if descendent is a child, grandchild, etc of node"""
        return descendant.path.startswith(node.path)

    def path_depth(self, node):
        """Returns the path depth of a particular node"""
        return node.path_depth

    def max_depth(self):
        """Returns the maximum depth of the tree"""
        return self.visit(None, lambda n, a: max(a, self.path_depth(n)), )

    def path_is_valid(self, node):
        """Returns True is a given path is valid for this treegrid"""
        return node in self.children(node.parent)

    def prepend(self, parent, values):
        """Inserts a new node (with values) before any other children of parent"""
        return self.insert(parent, 0, values)

    def remove(self, node):
        children = self.children(node.parent)
        if len(children) < 1:
            raise ValueError("Invalid node or node parent")
        deletion = None
        i = 0
        for i in range(len(children)):
            if children[i] == node:
                deletion = i
            if deletion is not None:
                self.visit(children[i], lambda grandchild, _: grandchild.path_changed(node.path, False))
        if deletion is None:
            raise ValueError("Invalid node path")
        del children[deletion]

    def visit(self, node, function, initial_accumulator = None, sort_key = None):
        """Visits all the nodes in a tree, calling function on each one.

           function should have the signature function(node, accumulator) and return new_accumulator
           If accumulators are not needed, the function must still accept a second parameter.

           The order of that the nodes are visited is always depth first, however, the order children are traversed can
           be set based on a sort_key function which should accept a node's values and return something that can be
           sorted to receive the desired order (similar to the sort/sorted key).

           We use the private _find_children function so that we don't have to re-traverse the tree
           for every node we descend further down
        """
        # Find_nodes is path dependent, whereas _visit is not
        # So in case the function modifies the node's path, find the nodes first
        children = self._find_children(node)
        accumulator = initial_accumulator
        # We split visit into two, so that we don't have to keep calling find_children to traverse the tree
        if node is not None:
            accumulator = function(node, initial_accumulator)
        if children is not None:
            if sort_key is not None:
                children = sorted(children, key = lambda (x, y): sort_key(x.values))
            accumulator = self._visit(children, function, accumulator, sort_key)
        return accumulator

    def _visit(self, list_of_children, function, accumulator, sort_key = None):
        """Visits all the nodes in a tree, calling function on each one"""
        if list_of_children is not None:
            for n, children in list_of_children:
                accumulator = function(n, accumulator)
                if sort_key is not None:
                    children = sorted(children, key = lambda (x, y): sort_key(x.values))
                accumulator = self._visit(children, function, accumulator, sort_key)
        return accumulator

class ColumnSortKey(object):
    def __init__(self, treegrid, column_name):
        self._index = None
        for i in treegrid.columns:
            if i.name.lower() == column_name.lower():
                self._index = i.index
        if self._index is None:
            raise ValueError("Column " + column_name + " not found in TreeGrid columns")

    def key(self, values):
        """The key function passed as the sort key"""
        return values[self._index]

def pretty_print(node, _accumulator):
    if node is not None:
        print "  " * node.path_depth, node.values, node.path

def build_example_treegrid():
    tg = TreeGrid([("Offset (V)", int), ("Offset (P)", int)])
    row = tg.append(None, [100, 200])
    three = tg.append(row, [200, 300])
    two = tg.append(None, [110, 210])
    tg.append(two, [210, 310])
    print repr(tg._children), two[0]
    four = tg.insert_before(None, two, [105, 205])
    tg.insert_after(None, four, [106, 206])
    tg.prepend(three, [300, 400])
    five = tg.prepend(row, [199, 299])
    # tg.remove(five)
    return tg

if __name__ == '__main__':
    tg = build_example_treegrid()
    tg.visit(None, pretty_print)
