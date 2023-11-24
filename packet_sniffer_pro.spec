# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['packet_sniffer_pro.py'],
    pathex=[],
    binaries=[],
    datas=[('C:/Users/admin1/Desktop/Packet_sniffer_pro/images/image1.jpg', 'images'), ('C:/Users/admin1/Desktop/Packet_sniffer_pro/images/image2.jpg', 'images'), ('C:/Users/admin1/Desktop/Packet_sniffer_pro/images/image3.jpg', 'images'), ('C:/Users/admin1/Desktop/Packet_sniffer_pro/images/image4.jpg', 'images'), ('C:/Users/admin1/Desktop/Packet_sniffer_pro/images/image5.jpg', 'images'), ('C:/Users/admin1/Desktop/Packet_sniffer_pro/images/image6.jpg', 'images'), ('C:/Users/admin1/Desktop/Packet_sniffer_pro/images/image7.jpg', 'images')],
    hiddenimports=['PIL', 'scapy'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='packet_sniffer_pro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
