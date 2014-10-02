__author__ = 'mike'

class DotRenderer(object):
    def __init__(self, columns, renderers, config):
        self._config = config
        self._columns = columns
        self._text_cell_renderers = renderers

    def description(self, node):
        output = []
        for column in self._columns:
            text = self._text_cell_renderers[column.index].render(node.values[column.index])
            output.append((column.name + ": " + text).replace("|", "_").replace("\"", "_"))
        return "|".join(output)

    def _add_node(self, node, data):
        outfd, accumulator = data
        accumulator[node] = max(accumulator.values()) + 1
        outfd.write("  Node" + str(accumulator[node]) + " [label=\"" + self.description(node) + "\"];\n")
        if accumulator[node.parent] != 0:
            outfd.write("  Node" + str(accumulator[node.parent]) + " -> Node" + str(accumulator[node]) + ";\n")
        return (outfd, accumulator)

    def render(self, outfd, grid):
        """Renders the TreeGrid in data out to the output file from the config options"""
        outfd.write("digraph output {\n  node[shape = Mrecord];\n  rankdir=LR;")
        grid.visit(None, self._add_node, (outfd, {None: 0}))
        outfd.write("}\n")
