"""Renderers

Renderers display the unified output format in some manner (be it text or file or graphical output"""

import collections

Column = collections.namedtuple('Column', ['index', 'name', 'type'])

class TreeNode(object):
    """Class representing a particular node in a tree grid"""
    def __init__(self, path, treegrid, parent, values):
        if not isinstance(treegrid, TreeGrid):
            raise TypeError("Treegrid must be an instance of TreeGrid")
        self._treegrid = treegrid
        self._parent = parent
        self._path = path
        self._validate_values(values)
        self._values = values

    def __repr__(self):
        return "<TreeNode [" + self._path + "] - " + repr(self._values) + ">"

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
        """Returns the parent node of this node"""
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
    """Class providing the interface for a TreeGrid (which contains TreeNodes)"""

    simple_types = {int, str, float, bytes}
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
        self._columns = converted_columns

    @property
    def columns(self):
        """Returns the available columns and their ordering and types"""
        return self._columns

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
            return None
        return children

    def values(self, node):
        """Returns the values for a particular node

           The values returned are mutable,
        """
        children = self._children
        if node is None:
            raise ValueError("Node must be a valid node within the TreeGrid")
        try:
            for path_component in node.path.split(self.path_sep):
                node, children = children[int(path_component)]
        except IndexError:
            return None
        return node.values

    def append(self, parent, values):
        """Adds a new node at the top level if parent is None, or under the parent node otherwise, after all other children."""
        children = self._find_children(parent)
        if children is None:
            children = []
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
        if children is None:
            raise IndexError("Invalid parent node")
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

        children = self._children
        if parent is not None:
            children = self._find_children(parent)
            if children is None:
                raise ValueError("Invalid parent node")

        if sibling is None:
            i = 0 if before else len(children)

        for i in range(len(children)):
            testnode, _ = children[i]
            if testnode == sibling:
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

    def path_is_valid(self, node):
        """Returns True is a given path is valid for this treegrid"""
        return node in [ n for n, _ in self._find_children(node.parent)]

    def prepend(self, parent, values):
        """Inserts a new node (with values) before any other children of parent"""
        return self.insert(parent, 0, values)

    def remove(self, node):
        children = self._find_children(node.parent)
        if children is None or len(children) < 1:
            raise ValueError("Invalid node or node parent")
        deletion = None
        i = 0
        for i in range(len(children)):
            potential_node, _ = children[i]
            if potential_node == node:
                deletion = i
            if deletion is not None:
                self.visit(potential_node, lambda grandchild, _: grandchild.path_changed(node.path, False))
        if deletion is None:
            raise ValueError("Invalid node path")
        del children[deletion]

    def visit(self, node, function, initial_accumulator = None):
        """Visits all the nodes in a tree, calling function on each one"""
        # Find_nodes is path dependent, whereas _visit is not
        # So in case the function modifies the node's path, find the nodes first
        children = self._find_children(node)
        accumulator = initial_accumulator
        if node is not None:
            accumulator = function(node, initial_accumulator)
        if children is not None:
            accumulator = self._visit(children, function, accumulator)
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
        print "  " * node.path_depth, node.values, node.path

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
