from volatility.renderers.basic import Renderer
import json

__author__ = 'mike'

class HTMLRenderer(Renderer):

    def __init__(self):
        pass

    def render_row(self, node, accumulator):
        return accumulator + [json.dumps(node.values)]

    def render(self, outfd, data):
        """Renders the treegrid to HTML"""
        if data.max_depth() > 1:
            raise NotImplementedError("HTML output for trees has not yet been implemented")
        column_titles = ", \n".join(["{ \"title\": \"" + column.name + "\"}" for column in data.columns])
        json = "[" + ", \n".join(data.visit(None, self.render_row, [])) + "]"
        outfd.write("""<html>
                       <head>
                         <link rel="stylesheet" type="text/css" href="http://cdn.datatables.net/1.10.2/css/jquery.dataTables.css">
                         <script type="text/javascript" language="javascript" src="http://code.jquery.com/jquery-1.11.1.min.js"></script>
                         <script type="text/javascript" language="javascript" src="http://cdn.datatables.net/1.10.2/js/jquery.dataTables.min.js"></script>
                         <script type="text/javascript" class="init">
                           var dataSet = """ + json + """;
                           $(document).ready(function() {
                             $('#page').html( '<table cellpadding="0" cellspacing="0" border="0" class="display" id="data"></table>' );
                             $('#data').dataTable( {
                                         "data": dataSet,
                                         "columns": [""" + column_titles + """
                                         ]
                             } );
                           } );

                          </script>
                       </head>
                       <body><div id="page"></div></body></html>""" + "\n")
