"""Diagnostic only: inspect native RELRO padding, never approve a release."""
import argparse, hashlib, json, struct, zipfile
from pathlib import Path

PAGE = 16384

def inspect(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected little-endian ELF64')
    phoff, shoff = struct.unpack_from('<QQ', data, 32)
    phsize, phcount, shsize, shcount, string_index = struct.unpack_from('<HHHHH', data, 54)
    loads, relros = [], []
    for i in range(phcount):
        kind, flags, offset, address, _, filesz, memsz, alignment = struct.unpack_from('<IIQQQQQQ', data, phoff+i*phsize)
        item = dict(address=address, end=address+memsz, flags=flags, offset=offset, filesz=filesz, alignment=alignment)
        if kind == 1: loads.append(item)
        if kind == 0x6474e552: relros.append(item)
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff+i*shsize) for i in range(shcount)]
    strings_header = headers[string_index]
    strings = data[strings_header[4]:strings_header[4]+strings_header[5]]
    sections = []
    for h in headers:
        name = strings[h[0]:strings.find(b'\0', h[0])].decode('utf-8', 'replace')
        if h[2] & 3 == 3 and h[5]:
            sections.append(dict(name=name, start=h[3], end=h[3]+h[5]))
    findings=[]
    for r in relros:
        start, end = r['address']//PAGE*PAGE, (r['end']+PAGE-1)//PAGE*PAGE
        # Writable allocated bytes protected only because of rounding indicate a hazard.
        hazards=[s for s in sections if (s['start']<r['address'] and s['end']>start) or (s['end']>r['end'] and s['start']<end)]
        findings.append(dict(raw_start=r['address'], raw_end=r['end'], raw_end_modulo_16k=r['end']%PAGE,
            protection_start=start, protection_end=end, writable_section_rounding_hazards=hazards,
            following_writable_loads=[l for l in loads if l['flags']&2 and l['address']>=r['end']]))
    return dict(sha256=hashlib.sha256(data).hexdigest(), load_segments=loads, relro=findings,
        diagnostic_only=True, runtime_16kb_verified=False, strict_modulo_passed=all(r['end']%PAGE==0 for r in relros))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a=p.parse_args()
    with zipfile.ZipFile(a.archive) as z:
        result={n:inspect(z.read(n)) for n in z.namelist() if n.endswith('.so') and any('/'+abi+'/' in n for abi in ('arm64-v8a','x86_64'))}
    report=dict(archive=str(a.archive.resolve()), archive_sha256=hashlib.sha256(a.archive.read_bytes()).hexdigest(), libraries=result)
    a.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'libraries':len(result),'output':str(a.output),'diagnostic_only':True}))

if __name__=='__main__': main()
