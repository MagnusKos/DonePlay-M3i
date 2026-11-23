#!/usr/bin/env python3
"""zsp_build.py — build ZSP400 (RK260x) code with the ORIGINAL RockTools
sdspI toolchain (sdcc/sdas/sdld) under wine, and emit firmware-ready
big-endian images + symbol maps.

Requires: wine, RockTools tree (FWTools install) with RockCompiler/sdspI.
Set ROCKTOOLS=/path/to/RockTools or pass --rocktools. Default points at the
private artifacts copy.

Usage:
  zsp_build.py asm  file.s [-o out.obj]
  zsp_build.py cc   file.c [-I dir ...] [-o out.obj]
  zsp_build.py link out.obj [more.obj ...] --lcf file.lcf [-o out.elf] [--crt0]
  zsp_build.py elf2bin out.elf [-o out.bin] [--sym out.sym] [--vma-offset N]
  zsp_build.py build file1.s file2.c... --lcf file.lcf -o prefix [--crt0]
"""
import argparse, os, struct, subprocess, sys, tempfile

DEF_ROCKTOOLS = ("/data/ReverseEngineering/ExplayM3i/REA-Session/artifacts/"
                 "oldweb/RockTools")

def rocktools(args):
    rt = args.rocktools or os.environ.get("ROCKTOOLS") or DEF_ROCKTOOLS
    sdsp = os.path.join(rt, "RockCompiler", "sdspI")
    if not os.path.isdir(sdsp):
        sys.exit(f"sdspI not found under {rt} (set ROCKTOOLS)")
    return sdsp

def wine(sdsp, tool):
    return ["wine", os.path.join(sdsp, "bin", tool + ".exe")]

def env(sdsp):
    e = dict(os.environ)
    e["WINEDEBUG"] = "-all"
    # SDSP_HOME: windows path of the dir CONTAINING sdspI (RockCompiler)
    rc = os.path.dirname(sdsp)
    e["SDSP_HOME"] = "Z:" + rc.replace("/", "\\") + "\\"
    return e

def run(sdsp, tool, *a):
    r = subprocess.run(wine(sdsp, tool) + list(a), env=env(sdsp),
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        sys.exit(f"{tool} failed (rc={r.returncode})")
    if r.stdout.strip():
        sys.stderr.write(r.stdout)
    return r

def read_elf(path):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF":
        sys.exit(f"{path}: not ELF")
    endian = "<" if d[5] == 1 else ">"
    (e_shoff,) = struct.unpack(endian + "I", d[32:36])
    e_shentsize, e_shnum, e_shstrndx = struct.unpack(endian + "HHH", d[46:52])
    shs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        shs.append(struct.unpack(endian + "IIIIIIIIII", d[o:o+40]))
    def shname(off):
        s = shs[e_shstrndx]
        t = d[s[4]:s[4]+s[5]]
        return t[off:t.find(b"\0", off)].decode()
    return d, endian, shs, shname

def swap16(b):
    return bytes(x for p in zip(b[1::2], b[0::2]) for x in p)

def elf2bin(elf, out_bin, out_sym, vma_offset):
    d, endian, shs, shname = read_elf(elf)
    secs = {}
    for sh in shs:
        name = shname(sh[0])
        if sh[1] == 1 and sh[5]:  # PROGBITS with size
            data = d[sh[4]:sh[4]+sh[5]]
            secs[name] = (sh[3], swap16(data))  # (addr, BE bytes)
    if out_bin:
        # single flat image of .text (concat all PROGBITS allocatable secs
        # sorted by addr is possible; default: .text only)
        if ".text" not in secs:
            sys.exit("no .text section")
        addr, data = secs[".text"]
        open(out_bin, "wb").write(data)
        print(f"wrote {out_bin}: {len(data)} bytes (BE), "
              f"ELF vma 0x{addr:x}, runtime base 0x{addr - vma_offset:x}"
              f" (vma-offset 0x{vma_offset:x})")
    if out_sym:
        syms = []
        for sh in shs:
            if shname(sh[0]) == ".symtab":
                strtab_sh = shs[sh[6]]
                strt = d[strtab_sh[4]:strtab_sh[4]+strtab_sh[5]]
                ent = sh[9] or 16
                cnt = sh[5] // ent
                for i in range(cnt):
                    o = sh[4] + i * ent
                    if o + 16 > sh[4] + sh[5]:
                        break
                    nm, value, size, info, other, shndx = struct.unpack(
                        endian + "IIIBBH", d[o:o+16])
                    name = strt[nm:strt.find(b"\0", nm)].decode()
                    if name and value:
                        syms.append((value - vma_offset, name, size))
        with open(out_sym, "w") as f:
            for a, n, s in sorted(syms):
                f.write(f"0x{a:04x}\t{n}\t0x{s:x}\n")
        print(f"wrote {out_sym}: {len(syms)} symbols")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rocktools")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("asm", "cc"):
        p = sub.add_parser(name)
        p.add_argument("src")
        p.add_argument("-o", "--out")
        p.add_argument("-I", action="append", default=[])
        p.add_argument("--sdopt", metavar="WRAPPER",
                       help="run the optimizer stage through this wrapper "
                            "(called as: WRAPPER in.s out.q [args...]); "
                            "enables the 3-stage cc -> opt -> asm pipeline")
    p = sub.add_parser("link")
    p.add_argument("objs", nargs="+")
    p.add_argument("--lcf", required=True)
    p.add_argument("-o", "--out")
    p.add_argument("--crt0", action="store_true")
    p.add_argument("--libc", action="store_true", default=True)
    p = sub.add_parser("elf2bin")
    p.add_argument("elf")
    p.add_argument("-o", "--out")
    p.add_argument("--sym")
    p.add_argument("--vma-offset", type=lambda x: int(x, 0), default=0x9000)
    p = sub.add_parser("build")
    p.add_argument("srcs", nargs="+")
    p.add_argument("--lcf", required=True)
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--crt0", action="store_true")
    p.add_argument("--keep", action="store_true")
    p.add_argument("--sdopt", metavar="WRAPPER",
                   help="optimizer wrapper (WRAPPER in.s out.q) for .c sources")
    args = ap.parse_args()
    sdsp = rocktools(args)
    tmp = tempfile.mkdtemp(prefix="zspbuild_")

    if args.cmd in ("asm", "cc"):
        out = args.out or os.path.splitext(args.src)[0] + ".obj"
        if args.cmd == "asm":
            run(sdsp, "sdas", "-o", out, args.src)
        elif getattr(args, "sdopt", None):
            s_file = os.path.splitext(out)[0] + ".s"
            q_file = os.path.splitext(out)[0] + ".q"
            inc = [i for I in args.I for i in ("-I", I)]
            inc += ["-I", os.path.join(sdsp, "include")]
            run(sdsp, "sdcc", "-O", "-S", args.src, "-o", s_file, *inc)
            subprocess.run([args.sdopt, s_file, q_file], check=True)
            run(sdsp, "sdas", "-o", out, q_file)
        else:
            inc = [i for I in args.I for i in ("-I", I)]
            inc += ["-I", os.path.join(sdsp, "include")]
            run(sdsp, "sdcc", "-c", args.src, "-o", out, *inc)
        print("ok:", out)
    elif args.cmd == "link":
        out = args.out or "a.out"
        objs = list(args.objs)
        if args.crt0:
            objs.insert(0, os.path.join(sdsp, "lib", "crt0.obj"))
        libs = [os.path.join(sdsp, "lib", "libc.a")] if args.libc else []
        run(sdsp, "sdld", "-T", args.lcf, "-o", out, *objs, *libs)
        print("ok:", out)
    elif args.cmd == "elf2bin":
        out = args.out or os.path.splitext(args.elf)[0] + ".bin"
        elf2bin(args.elf, out, args.sym, args.vma_offset)
    elif args.cmd == "build":
        objs = []
        for src in args.srcs:
            base = os.path.join(tmp, os.path.basename(os.path.splitext(src)[0]))
            obj = base + ".obj"
            if src.endswith(".s"):
                run(sdsp, "sdas", "-o", obj, src)
            elif getattr(args, "sdopt", None):
                s_file, q_file = base + ".s", base + ".q"
                run(sdsp, "sdcc", "-O", "-S", src, "-o", s_file,
                    "-I", os.path.dirname(os.path.abspath(src)),
                    "-I", os.path.join(sdsp, "include"))
                subprocess.run([args.sdopt, s_file, q_file], check=True)
                run(sdsp, "sdas", "-o", obj, q_file)
            else:
                run(sdsp, "sdcc", "-c", src, "-o", obj,
                    "-I", os.path.dirname(os.path.abspath(src)),
                    "-I", os.path.join(sdsp, "include"))
            objs.append(obj)
        if args.crt0:
            objs.insert(0, os.path.join(sdsp, "lib", "crt0.obj"))
        elf = args.out + ".out"
        run(sdsp, "sdld", "-T", args.lcf, "-o", elf, *objs,
            os.path.join(sdsp, "lib", "libc.a"))
        elf2bin(elf, args.out + ".bin", args.out + ".sym", 0x9000)
        print("ok:", args.out + ".bin", "+", args.out + ".sym")
        if args.keep:
            print("workdir:", tmp)

if __name__ == "__main__":
    main()
