#!/usr/bin/env python3
"""Validate and join the two binary parts. Refuses to overwrite any output."""
import argparse
import hashlib
import json
from pathlib import Path


def assemble(destination):
    folder = Path(__file__).resolve().parent
    manifest = json.loads((folder / 'manifest.json').read_text())
    destination = Path(destination)
    if destination.exists(): raise FileExistsError(destination)
    temporary = destination.with_name(destination.name + '.partial')
    if temporary.exists(): raise FileExistsError(temporary)
    total = hashlib.sha256(); size = 0
    try:
        with temporary.open('xb') as out:
            for record in manifest['parts']:
                name = record['file']
                if Path(name).name != name: raise ValueError('Unsafe part path')
                part = folder / name
                if part.stat().st_size != record['bytes']: raise ValueError('Part size mismatch: ' + name)
                h = hashlib.sha256()
                with part.open('rb') as inp:
                    for block in iter(lambda: inp.read(1024 * 1024), b''):
                        h.update(block); total.update(block); size += len(block); out.write(block)
                if h.hexdigest() != record['sha256']: raise ValueError('Part SHA-256 mismatch: ' + name)
        expected = manifest['assembly']
        if size != expected['bytes'] or total.hexdigest() != expected['sha256']:
            raise ValueError('Assembled PDF mismatch')
        temporary.rename(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('destination', type=Path, help='New PDF output path; parent directory must exist')
    print(assemble(p.parse_args().destination))
