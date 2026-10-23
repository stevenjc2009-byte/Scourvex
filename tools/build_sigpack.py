#!/usr/bin/env python3
"""Build the Scourvex signature pack from real ClamAV CVD files.

Usage: build_sigpack.py <dir-with-main.cvd-daily.cvd> <out.zip> [--mbz-key KEY]

Output zip (read by app/src/main/java/com/scourvex/app/security/SigPack.kt):
  manifest.json    versions, counts, build time
  md5.bin          "SVM1", u32 count, records sorted by (size, md5):
                   u32 size, 16-byte md5, u32 name index
  names.txt        one signature name per line (index into md5.bin)
  sha.txt          hex:size-or-*:name   (SHA1/SHA256, and MD5 with wildcard size)
  fp.txt           hex:size             (ClamAV false-positive whitelist)
  body.txt         N<TAB>ndb-line  /  L<TAB>ldb-line (only syntax the app's matcher supports)
  stalkerware.tsv  pkg<TAB>package<TAB>app  /  cert<TAB>SHA1<TAB>app
  mbz.txt          MalwareBazaar SHA256 of APK/DEX/ELF/JAR samples (only with --mbz-key)
"""
import csv
import datetime
import gzip
import io
import json
import re
import struct
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

BODY_FAMILIES = ("Andr.", "Unix.", "Multios.", "PUA.Andr.", "PUA.Unix.")
UA = "Scourvex-sigpack/1.0 (+https://github.com/stevenjc2009-byte/Scourvex)"

# Hex-signature tokens the app's matcher implements (security/HexPattern.kt).
TOKEN = re.compile(
    r"[0-9a-f]{2}|\?\?|[0-9a-f]\?|\?[0-9a-f]|\*|\{\d+\}|\{-\d+\}|\{\d+-\}|\{\d+-\d+\}|\[\d+-\d+\]"
    r"|\((?:[0-9a-f]{2})+(?:\|(?:[0-9a-f]{2})+)+\)"
)


def hex_ok(sig: str, floating: bool = True) -> bool:
    """Floating patterns need a 3-byte literal run for the app's anchor search."""
    sig = sig.lower()
    pos = 0
    run = best = 0
    while pos < len(sig):
        m = TOKEN.match(sig, pos)
        if not m:
            return False
        t = m.group(0)
        if t.startswith("("):
            alts = t[1:-1].split("|")
            if len({len(a) for a in alts}) != 1:
                return False
        if len(t) == 2 and all(c in "0123456789abcdef" for c in t):
            run += 1
            best = max(best, run)
        else:
            run = 0
        pos = m.end()
    return best >= (3 if floating else 1)


def offset_ok(off: str) -> bool:
    return bool(re.fullmatch(r"\*|\d+(,\d+)?|EOF-\d+(,\d+)?", off))


def read_cvd(path: Path) -> dict:
    raw = path.read_bytes()
    header = raw[:512].decode("ascii", "replace").split(":")
    files = {}
    # .cvd bodies are gzipped tar; freshclam's incrementally updated .cld bodies are plain tar.
    with tarfile.open(fileobj=io.BytesIO(raw[512:]), mode="r:*") as tar:
        for m in tar.getmembers():
            if m.isfile():
                files[m.name] = tar.extractfile(m).read().decode("utf-8", "replace")
    return {"version": int(header[2]), "sigs": int(header[3]), "built": header[1], "files": files}


def ldb_ok(line: str) -> bool:
    parts = line.split(";")
    if len(parts) < 4:
        return False
    for kv in parts[1].split(","):
        k, _, v = kv.partition(":")
        if k == "Target" and v not in ("0", "6"):
            return False
        if k == "Container" and v != "CL_TYPE_ZIP":
            return False
        if k not in ("Engine", "Target", "FileSize", "Container"):
            return False
    if not re.fullmatch(r"[0-9&|()=<>, ]+", parts[2]):
        return False
    for sub in parts[3:]:
        mods = ""
        if "::" in sub:
            sub, mods = sub.split("::", 1)
            if not set(mods) <= set("iwa"):
                return False
        off = "*"
        if ":" in sub:
            off, sub = sub.split(":", 1)
            if not offset_ok(off):
                return False
        if not hex_ok(sub, floating=not off[0].isdigit()):
            return False
    return True


def ndb_ok(line: str) -> bool:
    p = line.split(":")
    if len(p) < 4 or p[1] not in ("0", "6"):
        return False
    return offset_ok(p[2]) and hex_ok(p[3], floating=not p[2][0].isdigit())


def stalkerware() -> list[str]:
    url = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
    text = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=60).read().decode()
    out, name, section = [], None, None
    for raw in text.splitlines():
        if raw.startswith("- name:"):
            name, section = raw.split(":", 1)[1].strip(), None
        elif re.match(r"^  [a-z_]+:", raw):
            section = raw.strip().rstrip(":")
        elif raw.startswith("  - ") and name:
            val = raw[4:].strip()
            if section == "packages":
                out.append(f"pkg\t{val}\t{name}")
            elif section == "certificates" and re.fullmatch(r"[0-9A-Fa-f]{40}", val):
                out.append(f"cert\t{val.upper()}\t{name}")
    return out


def malwarebazaar(key: str) -> list[str]:
    url = f"https://mb-api.abuse.ch/v2/files/exports/{key}/full.csv.zip"
    data = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=600).read()
    keep = {"apk", "dex", "elf", "jar", "sh", "so"}
    out = []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        with z.open(z.namelist()[0]) as f:
            rows = csv.reader(io.TextIOWrapper(f, "utf-8", "replace"), skipinitialspace=True)
            for row in rows:
                if len(row) > 6 and not row[0].startswith("#") and row[6].strip('" ').lower() in keep:
                    out.append(row[1].strip('" ').lower())
    return out


def main() -> None:
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    mbz_key = sys.argv[sys.argv.index("--mbz-key") + 1] if "--mbz-key" in sys.argv else None
    cvds = {n: read_cvd(src / f"{n}.cvd" if (src / f"{n}.cvd").exists() else src / f"{n}.cld") for n in ("main", "daily")}
    files = {k: v for c in cvds.values() for k, v in c["files"].items()}

    ignored = set()
    for k, v in files.items():
        if k.endswith((".ign", ".ign2")):
            ignored |= {ln.split(":")[0].strip() for ln in v.splitlines() if ln.strip()}

    md5 = {}  # (size, md5bytes) -> name
    sha = []
    for k, v in files.items():
        if not k.endswith((".hdb", ".hsb", ".hdu", ".hsu")):
            continue
        pua = k.endswith("u")
        for ln in v.splitlines():
            p = ln.strip().split(":")
            if len(p) < 3 or p[2] in ignored:
                continue
            h, size, name = p[0].lower(), p[1], ("PUA." + p[2] if pua and not p[2].startswith("PUA.") else p[2])
            if len(h) == 32 and size.isdigit() and int(size) < 2**32:
                md5[(int(size), bytes.fromhex(h))] = name
            elif re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", h):
                sha.append(f"{h}:{size}:{name}")

    fp = []
    for k, v in files.items():
        if k.endswith((".fp", ".sfp")):
            for ln in v.splitlines():
                p = ln.strip().split(":")
                if len(p) >= 2 and re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{64}", p[0].lower()):
                    fp.append(f"{p[0].lower()}:{p[1]}")

    body, dropped = [], 0
    for k, v in files.items():
        kind = "N" if k.endswith((".ndb", ".ndu")) else "L" if k.endswith((".ldb", ".ldu")) else None
        if not kind:
            continue
        for ln in v.splitlines():
            ln = ln.strip()
            name = ln.split(";" if kind == "L" else ":")[0]
            if not name.startswith(BODY_FAMILIES) or name in ignored:
                continue
            if (ndb_ok if kind == "N" else ldb_ok)(ln):
                body.append(f"{kind}\t{ln}")
            else:
                dropped += 1

    names, recs = [], bytearray()
    for (size, h), name in sorted(md5.items()):
        recs += struct.pack("<I", size) + h + struct.pack("<I", len(names))
        names.append(name)
    stalk = stalkerware()
    mbz = malwarebazaar(mbz_key) if mbz_key else []

    manifest = {
        "format": 1,
        "built": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "clamav": {n: {"version": c["version"], "built": c["built"]} for n, c in cvds.items()},
        "counts": {"md5": len(names), "sha": len(sha), "fp": len(fp), "body": len(body),
                   "body_unsupported": dropped, "stalkerware": len(stalk), "malwarebazaar": len(mbz)},
    }
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=1))
        z.writestr("md5.bin", b"SVM1" + struct.pack("<I", len(names)) + bytes(recs))
        z.writestr("names.txt", "\n".join(names))
        z.writestr("sha.txt", "\n".join(sha))
        z.writestr("fp.txt", "\n".join(fp))
        z.writestr("body.txt", "\n".join(body))
        z.writestr("stalkerware.tsv", "\n".join(stalk))
        z.writestr("mbz.txt", "\n".join(mbz))
    print(json.dumps(manifest, indent=1))
    print("bytes", out.stat().st_size)


if __name__ == "__main__":
    main()
