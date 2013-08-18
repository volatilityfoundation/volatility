# Distorm3 hook
#
# This currently contains the hardcoded location for the standard distorm3.dll install
# It could be improved by carrying out a search, or using sys.path
#
# This also requires the distorm3 module to be modified with the following patch:

# import sys
# if hasattr(sys, '_MEIPASS'):
#     _distorm_path = sys._MEIPASS

datas = [ ("C:\python27\Lib\site-packages\distorm3\distorm3.dll", ''), ]
