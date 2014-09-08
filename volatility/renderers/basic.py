__author__ = 'mike'

import sys

from volatility.framework.interfaces import renderers as interface
from volatility.framework import renderers


class TextRenderer(interface.Renderer):
    def get_render_options(self):
        # FIXME: Fill in the docstring and provide render_options
        pass

    def __init__(self, options):
        interface.Renderer.__init__(self, options)
        self._options = options
        self._column_widths = []

    def render(self, grid):
        """Renders a text grid based on the contents of each element"""
        self.type_check(grid, renderers.TreeGrid)

        # FIXME: Separator should come from options
        sep = " | "

        max_level = -1
        column_maximum_widths = [max(len(column.name), column.format.width) for column in grid.columns]
        for (level, row) in grid.iterator():
            max_level = max(max_level, level)
            column_maximum_widths = [max(column_maximum_widths[column.index], len(
                ("{0:" + column.format.to_string() + "}").format(row.values[column.index]))) for column in grid.columns]

        for column in grid.columns:
            column.format.width = column_maximum_widths[column.index]
            column.format.fill = ' '
            # column.format.align = '<'

        # Run through the values and determine their maximum lengths, perhaps build up a two dimensional array
        # Then print out the headers and the values at their appropriate spacings
        # Potentially warn if the output is likely to be longer than the display area.

        headers = [("{0:" + renderers.FormatSpecification(width = column_maximum_widths[column.index], fill = ' ',
                                                          align = '^').to_string() + "}").format(column.name) for column
                   in
                   grid.columns]
        print(sep.join(headers))

        for (level, row) in grid.iterator():
            row_text = []
            for column in grid.columns:
                row_text.append(("{:" + column.format.to_string() + "}").format(row.values[column.index]))
            line = sep.join(row_text)
            sys.stdout.write(line + "\n")
