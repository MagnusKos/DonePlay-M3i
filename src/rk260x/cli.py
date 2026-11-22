"""`rkx` command-line interface for rk260x-tools."""

import argparse
import os
import sys


def _here():
    return os.path.dirname(os.path.abspath(__file__))


def _data():
    return os.path.join(_here(), '..', '..', 'data')


def cmd_status(args):
    from .rockusb import RockUsb, RockError, device_mode, find_device
    try:
        dev = find_device()
    except RockError as e:
        print(e)
        return 1
    print('found 071b:3202, mode:', device_mode(dev))
    return 0


def cmd_info(args):
    import time
    from . import rockusb
    r = rockusb.boot_default_images()
    r.test_unit_ready()
    print('flash ID:', r.read_flash_id().hex())
    return 0


def cmd_flash(args):
    from . import flasher
    flasher.cmd_full_replay(args.stream)
    return 0


def cmd_build(args):
    from . import flasher
    return flasher.cmd_build(args.rfw, args.out)


def cmd_derive(args):
    from .derive import derive
    return derive(args.capture, args.rfw)


def cmd_rfw_info(args):
    from . import rfw
    rfw.cmd_info(args.rfw_path)
    return 0


def cmd_rfw_extract(args):
    from . import rfw
    rfw.cmd_extract(args.rfw_path, args.outdir)
    return 0


def cmd_gui(args):
    from .gui import viewer
    viewer.run(args.map, args.firmware)
    return 0


def cmd_zspdis(args):
    from .zspdis import disasm
    data = open(args.binary, 'rb').read()
    print('\n'.join(disasm(data, args.base)))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog='rkx', description='rk260x-tools')
    sub = ap.add_subparsers(dest='cmd', required=True)

    sub.add_parser('status', help='detect player (upgrade mode)')
    sub.add_parser('info', help='boot updater + read flash ID')

    p = sub.add_parser('flash', help='flash a stream (default: derived/full_stream.json = original firmware)')
    p.add_argument('stream', nargs='?', default=None)

    p = sub.add_parser('build', help='build flash stream from (modified) .rfw')
    p.add_argument('rfw')
    p.add_argument('out', nargs='?', default='built_stream.json')

    p = sub.add_parser('derive', help='derive flasher artifacts from usbmon capture')
    p.add_argument('capture', help='pcapng of a real update session')
    p.add_argument('--rfw', default=None, help='original .rfw for page template')

    p = sub.add_parser('rfw-info', help='firmware container info')
    p.add_argument('rfw_path')
    p = sub.add_parser('rfw-extract', help='extract/decrypt firmware stages')
    p.add_argument('rfw_path')
    p.add_argument('outdir')

    p = sub.add_parser('gui', help='image browser/editor')
    p.add_argument('--map', default=None, help='.tl map')
    p.add_argument('--firmware', default=None, help='.rfw to open')

    p = sub.add_parser('zspdis', help='ZSP400 disassembler')
    p.add_argument('binary')
    p.add_argument('base', nargs='?', type=lambda x: int(x, 0), default=0)

    args = ap.parse_args(argv)
    return {
        'status': cmd_status, 'info': cmd_info, 'flash': cmd_flash,
        'build': cmd_build, 'derive': cmd_derive,
        'rfw-info': cmd_rfw_info, 'rfw-extract': cmd_rfw_extract,
        'gui': cmd_gui, 'zspdis': cmd_zspdis,
    }[args.cmd](args)


if __name__ == '__main__':
    sys.exit(main())
