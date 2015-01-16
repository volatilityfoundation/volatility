import StringIO
from volatility.renderers.basic import Renderer
import json

__author__ = 'mike'

class HTMLRenderer(Renderer):

    def __init__(self):
        pass

    def render_row(self, node, accumulator):
        return accumulator + [node.values]

    def render(self, outfd, data):
        """Renders the treegrid to HTML"""
        # TODO: Implement tree structure in HTML
        if data.max_depth() > 1:
            raise NotImplementedError("HTML output for trees has not yet been implemented")
        column_titles = ", \n".join(["{ \"title\": \"" + column.name + "\"}" for column in data.columns])
        json_input = {"columns": [column.name for column in data.columns], "rows": data.visit(None, self.render_row, [])}
        json_text = json.dumps(json_input)
        outfd.write("""<html>
                       <head>
                         <link rel="stylesheet" type="text/css" href="http://cdn.datatables.net/1.10.2/css/jquery.dataTables.css">
                         <script type="text/javascript" language="javascript" src="http://code.jquery.com/jquery-1.11.1.min.js"></script>
                         <script type="text/javascript" language="javascript" src="http://cdn.datatables.net/1.10.2/js/jquery.dataTables.min.js"></script>
                         <script type="text/javascript" class="init">
                           var dataSet = """ + json_text + """;
                           $(document).ready(function() {
                             $('#page').html( '<table cellpadding="0" cellspacing="0" border="0" class="display" id="data"></table>' );
                             $('#data').dataTable( {
                                         "data": dataSet['rows'],
                                         "columns": [""" + column_titles + """]
                             } );
                           } );

                          </script>
                       </head>
                       <body><div id="page"></div></body></html>""" + "\n")

class JSONRenderer(Renderer):
    def _add_node(self, node, data):
        # columns: list of column names
        # rows: list of dicts representing root nodes
        # nodes: dict( key = node object, value = dict representation )
        columns, rows, nodes = data
        n = {}
        # translate node object to dict
        for i in range(len(columns)):
            n[columns[i]] = node.values[i]
        # associate node object to dict representation
        nodes[node] = n
        # if this is a root node
        if node.parent == None:
            # add to list of rows
            rows.append(nodes[node])
        else:
            # add to parent's children list
            # ASSUMES there is no column named __children
            if '__children' not in nodes[node.parent]:
                nodes[node.parent]['__children'] = []
            nodes[node.parent]['__children'].append(nodes[node])
        return columns, rows, nodes

    def render(self, outfd, data):
        """Renders a treegrid as an array of objects in JSON format"""
        # TODO: Output (basic) type information in JSON
        columns = [column.name for column in data.columns]
        rows = []
        nodes = {}
        columns, rows, nodes = data.visit(None, self._add_node, (columns, rows, nodes))
        return outfd.write(json.dumps(rows))

