
import os

projpath = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

modules = set(['volatility.plugins'])

for dirpath, _dirnames, filenames in os.walk(os.path.join(projpath, 'volatility', 'plugins')):
    dirpath = dirpath[len(os.path.join(projpath, 'volatility', 'plugins')):]
    if dirpath and dirpath[0] == os.path.sep:
        dirpath = dirpath[1:]
    for filename in filenames:
        path = os.path.join(dirpath, os.path.splitext(filename)[0])
        if "/." in path:
            continue
        if "__" in path:
            continue

        path = path.replace("-", "_")
        path = path.replace(os.path.sep, ".")

        modules.add("volatility.plugins." + path)

hiddenimports = list(modules)
