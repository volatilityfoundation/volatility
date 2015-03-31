"""Renderers

Renderers display the unified output format in some manner (be it text or file or graphical output"""

import collections
import types

Column = collections.namedtuple('Column', ['index', 'name', 'type'])

class TreePopulationError(StandardError):
    """Exception class for accessing functions on an partially populated tree."""
    pass

class TreeNode(collections.Sequence):
    """Class representing a particular node in a tree grid"""
    def __init__(self, path, treegrid, parent, values):
        if not isinstance(treegrid, TreeGrid):
            raise TypeError("Treegrid must be an instance of TreeGrid")
        self._treegrid = treegrid
        self._parent = parent
        self._path = path
        self._validate_values(values)
        self._values = treegrid.RowStructure(*values)

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
                if not (type(values[index]) == long and column.type == int):
                    raise TypeError(
                    "Values item with index " + repr(index) + " is the wrong type for column " + \
                    repr(column.name) + " (got " + str(type(values[index])) + " but expected " + \
                    str(column.type) + ")")

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

    The structure of a TreeGrid is designed to maintain the structure of the tree in a single object.
    For this reason each TreeNode does not hold its children, they are managed by the top level object.
    This leaves the Nodes as simple data carries and prevents them being used to manipulate the tree as a whole.
    This is a data structure, and is not expected to be modified much once created.

    Carrying the children under the parent makes recursion easier, but then every node is its own little tree
    and must have all the supporting tree functions.  It also allows for a node to be present in several different trees,
    and to create cycles.
    """

    simple_types = set([int, long, str, float, bytes])
    path_sep = "|"

    def __init__(self, columns, generator):
        """Constructs a TreeGrid object using a specific set of columns

        The TreeGrid itself is a root element, that can have children but no values.
        The TreeGrid does *not* contain any information about formatting,
        these are up to the renderers and plugins.

        :param columns: A list of column tuples made up of (name, type).
        :param generator: A generator that populates the tree/grid structure
        """
        self._populated = False
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
        self.RowStructure = collections.namedtuple("RowStructure", [self._sanitize(column.name) for column in converted_columns])
        self._columns = converted_columns
        if generator is None:
            generator = []
        generator = iter(generator)

        self._generator = generator

    def _sanitize(self, text):
        output = ""
        for letter in text.lower():
            if letter != ' ':
                output += (letter if letter in 'abcdefghiljklmnopqrstuvwxyz_' else '_')
        return output

    def populate(self, func = None, initial_accumulator = None):
        """Generator that returns the next available Node

           This is equivalent to a one-time visit.
        """
        accumulator = initial_accumulator
        if func is None:
            func = lambda _x, _y: None

        if not self.populated:
            prev_nodes = []
            for (level, item) in self._generator:
                parent_index = min(len(prev_nodes), level)
                parent = prev_nodes[parent_index - 1] if parent_index > 0 else None
                treenode = self._append(parent, item)
                prev_nodes = prev_nodes[0: parent_index] + [treenode]
                accumulator = func(treenode, accumulator)
        self._populated = True

    @property
    def populated(self):
        """Indicates that population has completed and the tree may now be manipulated separately"""
        return self._populated

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

    def _append(self, parent, values):
        """Adds a new node at the top level if parent is None, or under the parent node otherwise, after all other children."""
        parent_path = ""
        children = self._find_children(parent)
        if parent is not None:
            parent_path = parent.path + self.path_sep
        newpath = parent_path + str(len(children))
        tree_item = TreeNode(newpath, self, parent, values)
        children.append((tree_item, []))
        return tree_item

    def _insert(self, parent, position, values):
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
        if not self.populated:
            self.populate()

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
