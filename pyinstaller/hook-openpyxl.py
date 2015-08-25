# Openpyxl hook
#
# This currently contains the hardcoded location for the .constants.json file
# It could be improved by carrying out a search, or using sys.path
#
# This also requires the openpyxl module to be modified with the following patch:

# import sys
# if hasattr(sys, '_MEIPASS'):
#     here = sys._MEIPASS

import os
import sys

datas = []

for path in sys.path:
  datas.append((os.path.join(path, "openpyxl", ".constants.json"), ""))

