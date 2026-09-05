"""Reproduce the test1.zip investigation using Python 3 standard library only.

Usage: python analyze.py path/to/test1.zip --output report.json
The ZIP is read in memory; no archive member is extracted or executed.
"""
import argparse
import hashlib
import json
import zipfile
from collections import Counter
from decimal import Decimal, localcontext
from pathlib import Path


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def pi_digits(count=1000):
    # Chudnovsky: ~14 decimal digits per term, with 100 guard digits.
    with localcontext() as ctx:
        ctx.prec = count + 100
        m, l, x, k = 1, 13591409, 1, 6
        total = Decimal(l)
        for i in range(1, (count + 100) // 14 + 2):
            m = m * (k**3 - 16*k) // i**3
            l += 545140134
            x *= -262537412640768000
            total += Decimal(m*l) / x
            k += 12
        value = 426880 * Decimal(10005).sqrt() / total
        return format(value, 'f')[:count + 2]


def analyze(path):
    archive_bytes = Path(path).read_bytes()
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise ValueError('ZIP CRC validation failed')
        entries = [entry for entry in archive.infolist() if not entry.is_dir()]
        names = [entry.filename for entry in entries]
        if len(set(names)) != len(names):
            raise ValueError('Duplicate archive member names require separate handling')
        if sum(entry.file_size for entry in entries) > 100_000_000:
            raise ValueError('Archive exceeds the audit size limit')
        files = {entry.filename: archive.read(entry) for entry in entries}

    # Hash groups identify candidate groups; full-byte equality is checked too.
    hash_counts = Counter(sha256(value) for value in files.values())
    majority_hash, majority_count = hash_counts.most_common(1)[0]
    if majority_count <= len(files) / 2:
        raise ValueError('No strict majority; cannot select a unique baseline')
    baseline_name = min(name for name, data in files.items() if sha256(data) == majority_hash)
    baseline = files[baseline_name]
    exact_count = sum(data == baseline for data in files.values())
    if exact_count != majority_count:
        raise ValueError('Digest group and byte-equality group disagree')
    anomalies = []
    for name, data in sorted(files.items()):
        if data == baseline:
            continue
        if len(data) != len(baseline):
            raise ValueError('Different file lengths require insertion/deletion alignment')
        changes = []
        for offset, (before, after) in enumerate(zip(baseline, data)):
            if before == after:
                continue
            changes.append({
                'offset': offset, 'position': offset + 1,
                'line': baseline[:offset].count(b'\n') + 1,
                'column': offset - baseline.rfind(b'\n', 0, offset),
                'decimalPosition': offset - 1,
                'before': chr(before), 'after': chr(after),
                'beforeHex': f'{before:02X}', 'afterHex': f'{after:02X}'
            })
        anomalies.append({'name': name, 'size': len(data), 'sha256': sha256(data),
                          'changes': changes, 'text': data.decode('ascii')})

    all_data = list(files.values())
    report = {
        'archive': {'name': Path(path).name, 'sha256': sha256(archive_bytes),
                    'bytes': len(archive_bytes), 'crcVerified': True},
        'total': len(files), 'identical': exact_count,
        'baseline': {'name': baseline_name, 'sha256': majority_hash,
                     'size': len(baseline), 'text': baseline.decode('ascii')},
        'anomalies': anomalies,
        'checks': {
            'hashGroupCounts': sorted(hash_counts.values(), reverse=True),
            'directByteEquality': True,
            'allAscii': all(all(byte < 128 for byte in data) for data in all_data),
            'onlyDigitsAndDot': all(all(byte in b'0123456789.' for byte in data) for data in all_data),
            'noBom': all(not data.startswith((b'\xef\xbb\xbf', b'\xff\xfe', b'\xfe\xff')) for data in all_data),
            'noLineBreaks': all(b'\r' not in data and b'\n' not in data for data in all_data),
            'noWhitespace': all(not any(chr(byte).isspace() for byte in data) for data in all_data),
            'sizes': sorted(set(map(len, all_data))),
            'expectedNames': sorted(names) == [f'file_{i:04d}.txt' for i in range(1, 1001)],
            'baselineMatchesPi': baseline == pi_digits(1000).encode('ascii'),
            'piMethod': 'Chudnovsky formula; Decimal precision 1100; truncation to 1000 decimal places'
        },
        'manifest': [{'name': name, 'size': len(data), 'sha256': sha256(data),
                      'different': data != baseline} for name, data in sorted(files.items())]
    }
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = analyze(args.archive)
    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items() if key != 'manifest'}, ensure_ascii=False, indent=2))
