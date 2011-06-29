# -*- mode: python -*-
projpath = os.path.dirname(os.path.abspath(SPEC))

def get_plugins(list):
    for item in list:
        if item[0].startswith('volatility.plugins') and not (item[0] == 'volatility.plugins' and '__init__.py' in item[1]):
            yield item

exeext = ".exe" if 'win' in sys.platform else ""

a = Analysis([os.path.join(HOMEPATH, 'support/_mountzlib.py'),
              os.path.join(HOMEPATH, 'support/useUnicode.py'),
              os.path.join(projpath, 'vol.py')],
              pathex = [HOMEPATH],
              hookspath = [os.path.join(projpath, 'pyinstaller')])
pyz = PYZ(a.pure - set(get_plugins(a.pure)),
          name = os.path.join(BUILDPATH, 'vol.pkz'))
plugins = Tree(os.path.join(projpath, 'volatility', 'plugins'),
               os.path.join('plugins'))
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          plugins,
          name = os.path.join(projpath, 'dist', 'pyinstaller', 'volatility' + exeext),
          debug = False,
          strip = False,
          upx = True,
          icon = os.path.join(projpath, 'resources', 'volatility.ico'),
          console = 1)
