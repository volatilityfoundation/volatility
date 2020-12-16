# Volatility
# Copyright (C) 2008-2015 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

from datetime import datetime
try:
  from elasticsearch import Elasticsearch
  from elasticsearch import helpers
except ImportError:
  Elasticsearch = None
from volatility.renderers.basic import Renderer, Bytes
from volatility import debug
import uuid


class ElasticRenderer(Renderer):

    def __init__(self, plugin_name, config):
        if not Elasticsearch:
            debug.error("You must install the Elasticsearch python client" \
                    ":\n\thttps://pypi.org/project/elasticsearch/")
        self._plugin_name = plugin_name
        self._config = config
        self._es = None
        self._type = 'volatility'
        self._accumulator = []

    def render(self, outfd, grid):
        self._es = Elasticsearch([self._config.ELASTIC_URL])

        def _add_multiple_row(node, accumulator):
            row = node.values._asdict()
            if 'start' in row and row['start'][:-5] != '':
                row['datetime'] = datetime.strptime(row['start'][:-5],"%Y-%m-%d %H:%M:%S %Z")
            else:
                row['datetime'] = datetime.now()
                
            row['plugin'] = self._plugin_name
            accumulator.append({
                '_index': self._config.INDEX,
                '_type': self._type,
                '_id': uuid.uuid4().hex,
                '_source': row
                })
            if len(accumulator) > 500:
                helpers.bulk(self._es, accumulator)
                accumulator = []
            self._accumulator = accumulator
            return accumulator

        grid.populate(_add_multiple_row, self._accumulator)

        #Insert last nodes
        if len(self._accumulator) > 0:
            helpers.bulk(self._es, self._accumulator)
