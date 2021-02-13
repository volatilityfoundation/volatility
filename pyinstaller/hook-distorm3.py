# Distorm3 hook
#
# This currently contains the hardcoded location for the standard distorm3.dll install
# It could be improved by carrying out a search, or using sys.path
#
# This also requires the distorm3 module to be modified with the following patch:

# import sys
# if hasattr(sys, '_MEIPASS'):
#     _distorm_path = sys._MEIPASS

import os
import sys

datas = []

for path in sys.path:
    if os.path.exists(os.path.join(path, "distorm3", "distorm3.dll")):
        datas.append((os.path.join(path, "distorm3", "distorm3.dll"), "."))
    if os.path.exists(os.path.join(path, "distorm3", "libdistorm3.so")):
        datas.append((os.path.join(path, "distorm3", "libdistorm3.so"), "."))

