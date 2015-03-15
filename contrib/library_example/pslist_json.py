# Volatility
# Copyright (c) 2015 Michael Ligh (michael.ligh@mnin.org)
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

import sys 
import volatility.plugins.taskmods as taskmods 
import libapi 

def main():

    ## sys.argv[1] = volatility profile 
    ## sys.argv[2] = full path on disk to your memory sample

    config = libapi.get_config(sys.argv[1], sys.argv[2])
    data = libapi.get_json(config, taskmods.PSList)

    ## `data` now contains json with two keys: `columns` and `rows`, where `columns`
    ## contains a list of column headings (matching the corresponding volatility 
    ## plugin output) and `rows` contains a list of the values for each object found.

    ## you can either print/save all columns, or you can drill down to a particular 
    ## column by getting the desired column's index as shown below and then accessing
    ## the index in each row. the following example prints each process' name. 
    
    name_index = data['columns'].index('Name')

    for row in data['rows']:
        print row[name_index]

if __name__ == "__main__":
    main()