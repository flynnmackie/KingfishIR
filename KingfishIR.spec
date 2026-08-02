# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

# Bundle read-only resources at the app root so resource_path() (which looks in
# sys._MEIPASS when frozen) can find them in the packaged exe.
datas = [
    ('kingfisher.ico', '.'),
    ('kingfisher.png', '.'),
]
binaries = []
hiddenimports = []

# Collect the transport / crypto / SMB dependencies in full so nothing is
# missing at runtime in the packaged exe.
for pkg in ('pypsrp', 'paramiko', 'cryptography', 'pyspnego', 'smbprotocol'):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='KingfishIR',
    icon='kingfisher.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
