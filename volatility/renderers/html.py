import StringIO
from volatility.renderers.basic import Renderer

try:
    import ujson as json
except ImportError:
    import json

__author__ = 'mike'

class HTMLRenderer(Renderer):

    def __init__(self):
        pass

    def render(self, outfd, data):
        """Renders the treegrid to HTML"""
        column_titles = ", \n".join(["{ \"title\": \"" + column.name + "\"}" for column in data.columns])
        json = StringIO.StringIO()
        JSONRenderer().render(json, data)
        outfd.write("""<html>
                       <head>
                         <link rel="stylesheet" type="text/css" href="http://cdn.datatables.net/1.10.2/css/jquery.dataTables.css">
                         <script type="text/javascript" language="javascript" src="http://code.jquery.com/jquery-1.11.1.min.js"></script>
                         <script type="text/javascript" language="javascript" src="http://cdn.datatables.net/1.10.2/js/jquery.dataTables.min.js"></script>
                         <script type="text/javascript" class="init">
                           var dataSet = """ + json.getvalue() + """;
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
    def render_row(self, node, accumulator):
        return accumulator + [node.values]

    def render(self, outfd, data):
        """Renderers a treegrid as columns/row items in JSON format"""
        # TODO: Implement tree structure in JSON
        if data.max_depth() > 1:
            raise NotImplementedError("JSON output for trees has not yet been implemented")
        # TODO: Output (basic) type information in JSON
        json_input = {"columns": [column.name for column in data.columns], "rows": data.visit(None, self.render_row, [])}
        return outfd.write(json.dumps(json_input,ensure_ascii=False))
