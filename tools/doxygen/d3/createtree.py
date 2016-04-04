import os
import json

'''
Author: Gleeda <jamie@memoryanalysis.net>

modified from:
  http://stackoverflow.com/questions/25226208/represent-directory-tree-as-json

Quick and Dirty.  Run from the Volatility root directory and redirect:

python createtree.py > OUTPUT/d3/vol.json

'''

link = "https://github.com/volatilityfoundation/volatility/blob/master/"
ignore = [".git", "doxygen", ".gitignore", ".gitattributes"]

def path_to_dict(path):
    if path == ".":
        d = {'name': os.path.basename("root")}
    else:
        d = {'name': os.path.basename(path)}
        d['link'] = str(link + path).replace("/.", "")
    if os.path.isdir(path):
        d['type'] = "directory"
        d['children'] = [path_to_dict(os.path.join(path, x)) for x in os.listdir(path) if x not in ignore]
    else:
        d['type'] = "file"
    return d

print json.dumps(path_to_dict('.'))
