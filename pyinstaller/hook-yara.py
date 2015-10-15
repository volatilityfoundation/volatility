import os
import sys

datas = []

for path in sys.path:
  datas.append(("yara.pyd", ""))
  datas.append(("yara.so", ""))