import os
import sys

datas = []

for path in sys.path:
    if os.path.exists(os.path.join(path, "yara.pyd")):
        datas.append((os.path.join(path, "yara.pyd"), "."))
    if os.path.exists(os.path.join(path, "yara.so")):
        datas.append((os.path.join(path, "yara.so"), "."))
