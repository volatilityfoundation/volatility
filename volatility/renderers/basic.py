__author__ = 'mike'

import sys

from volatility.interfaces import renderers as interface
from volatility import renderers

class Address(int):
    """Integer class to allow renderers to differentiate between addresses and numbers"""
    def __new__(cls, number, *args, **kwargs):
        return number

    def __init__(self, number, max_bits = 32):
        self.max_bits = max_bits

class CellRenderer(object):
    """Class to handle rendering each cell of a grid"""

    def render(self):
        """Render an individual cell"""

class TextRenderer(interface.Renderer):
    def get_render_options(self):
        # FIXME: Fill in the docstring and provide render_options
        pass

    def __init__(self, options, cell_renderer):
        interface.Renderer.__init__(self, options)
        self.type_check(cell_renderer, CellRenderer)
        self._cell_renderer = cell_renderer
        self._options = options

    def render(self, grid):
        """Renders a text grid based on the contents of each element"""
        self.type_check(grid, renderers.TreeGrid)

        # FIXME: Separator should come from options
        sep = " | "
        indent = "  "

        max_level = -1
        column_maximum_widths = [len(column.name) for column in grid.columns]
        for (level, row) in grid.iterator():
            max_level = max(max_level, level)
            column_maximum_widths = [max(column_maximum_widths[column.index], len(self._cell_renderer.render(row[column.index]))) for column in grid.columns]

        # Run through the values and determine their maximum lengths, perhaps build up a two dimensional array
        # Then print out the headers and the values at their appropriate spacings
        # Potentially warn if the output is likely to be longer than the display area.

        headers = [("{0:" + renderers.FormatSpecification(width = column_maximum_widths[column.index],
                                                          fill = ' ',
                                                          align = '^').to_string() + "}").format(column.name) for column
                   in
                   grid.columns]
        print((indent * max_level) + sep.join(headers))

        for (level, row) in grid.iterator():
            row_text = []
            for column in grid.columns:
                row_text.append(self._cell_renderer.render(row.values[column.index]))
            line = (indent * level) + sep.join(row_text)
            sys.stdout.write(line + "\n")
