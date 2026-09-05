"""Independently inspect the supplied test1.zip using Python 3.8+ standard library.

Run from the directory containing the archive:
    python verify.py
Or pass paths explicitly, from any working directory:
    python verify.py /path/to/test1.zip --output /path/to/verification.json

The default input is ./test1.zip. The default report is ./verification.json.
No archive entries are extracted and no external packages are required.
"""

import argparse
from collections import Counter
from hashlib import sha256
from pathlib import Path
from decimal import Decimal, localcontext
import json, zipfile

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('archive', nargs='?', type=Path, default=Path('test1.zip'), help='ZIP file; default: ./test1.zip')
parser.add_argument('--output', type=Path, default=Path('verification.json'), help='JSON report; default: ./verification.json')
args = parser.parse_args()
archive_path = args.archive.resolve()
with zipfile.ZipFile(archive_path) as z:
    corrupt_entry = z.testzip()
    if corrupt_entry is not None:
        raise ValueError(f'ZIP CRC mismatch: {corrupt_entry}')
    entries = z.infolist()
    files = [(i.filename, z.read(i)) for i in entries if not i.is_dir()]
    if not files:
        raise ValueError('The archive contains no files.')
    byte_groups = Counter(data for name, data in files)
    common, common_count = byte_groups.most_common(1)[0]
    if common_count <= len(files) / 2:
        raise ValueError('No exact byte group contains more than half the files.')
    with localcontext() as ctx:
        ctx.prec = 1120
        a, b, t, power = Decimal(1), Decimal(1) / Decimal(2).sqrt(), Decimal(1) / 4, Decimal(1)
        for _ in range(13):
            next_a = (a + b) / 2
            b = (a * b).sqrt()
            t -= power * (a - next_a) ** 2
            a, power = next_a, power * 2
        computed_pi = (a + b) ** 2 / (4 * t)
        pi_digits = format(computed_pi, 'f')[:1002].encode('ascii')
    differences = []
    for name, data in files:
        if data == common:
            continue
        if len(data) != len(common):
            raise ValueError(f'{name}: this archive-specific audit expects equal file lengths; insertion/deletion analysis is required.')
        positions = [i for i, (a, b) in enumerate(zip(common, data)) if a != b]
        differences.append({
            'name': name,
            'sha256': sha256(data).hexdigest(),
            'changed_byte_count': len(positions),
            'changes': [{
                'byte_offset_zero_based': p,
                'byte_position_one_based': p+1,
                'line_one_based': common[:p].count(b'\n')+1,
                'column_one_based': p-common.rfind(b'\n', 0, p),
                'decimal_digit_one_based': p-1,
                'before_ascii': chr(common[p]),
                'after_ascii': chr(data[p]),
                'before_hex': hex(common[p]),
                'after_hex': hex(data[p]),
            } for p in positions],
            'context_before': common[max(0,min(positions)-15):max(positions)+16].decode('ascii'),
            'context_after': data[max(0,min(positions)-15):max(positions)+16].decode('ascii'),
        })
    result = {
        'archive': {'sha256': sha256(archive_path.read_bytes()).hexdigest(), 'bytes': archive_path.stat().st_size, 'entries': len(entries), 'directories': sum(i.is_dir() for i in entries), 'uncompressed_bytes': sum(i.file_size for i in entries), 'crc_all_pass': True},
        'file_count': len(files),
        'exact_byte_group_counts': sorted(byte_groups.values(), reverse=True),
        'grouping_method': 'Counter keyed by complete bytes values; SHA-256 is recorded separately, not used to determine equality.',
        'sha256_group_counts': sorted(Counter(sha256(data).hexdigest() for _, data in files).values(), reverse=True),
        'baseline': {'sha256': sha256(common).hexdigest(), 'count': common_count, 'bytes': len(common)},
        'baseline_matches_pi_truncated_at_1000_decimals': common == pi_digits,
        'pi_verification': 'Gauss-Legendre algorithm, Decimal precision 1120, 13 iterations, first 1000 decimal digits',
        'all_ascii': all(data.isascii() for _, data in files),
        'all_strict_utf8': all(data.decode('utf-8').encode('utf-8') == data for _, data in files),
        'all_sizes': sorted({len(data) for _, data in files}),
        'all_byte_values': sorted(set(b for _, data in files for b in data)),
        'all_no_bom': all(not data.startswith((b'\xef\xbb\xbf', b'\xff\xfe', b'\xfe\xff', b'\x00\x00\xfe\xff')) for _, data in files),
        'all_newline_byte_counts': sorted({(data.count(b'\r'), data.count(b'\n')) for _, data in files}),
        'all_decimal_digits': all(data.startswith(b'3.') and len(data[2:]) == 1000 and data[2:].isdigit() for _, data in files),
        'file_names_expected': len(files) == 1000 and {name for name, _ in files} == {f'file_{i:04d}.txt' for i in range(1,1001)},
        'duplicate_file_names': sorted(name for name, count in Counter(name for name, _ in files).items() if count > 1),
        'differences': differences,
    }
    target = args.output.resolve()
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
