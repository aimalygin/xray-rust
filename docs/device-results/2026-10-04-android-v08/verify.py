#!/usr/bin/env python3
"""Verify report hashes and aggregate verdicts against preserved event rows."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def read_json(path):
    return json.loads(path.read_text())


def check_report(root, followup):
    manifest = read_json(root / 'manifest.json')
    for item in manifest['artifacts']:
        path = (root / item['path']).resolve()
        assert path.is_relative_to(root.resolve()), item['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256'], path
    events = [json.loads(line) for line in (root / 'events.jsonl').read_text().splitlines()]
    assert sum(x['kind'] == 'case-pass' for x in events) == 14
    assert not any(x['kind'] == 'case-fail' for x in events)
    functional = [e for e in events if e['kind'] in ('traffic', 'close-recovery', 'cancel-start-recovery')]
    for key, field in [('http-passed', 'functionalHttpPassed'), ('udp-passed', 'functionalUdpPassed')]:
        assert sum(int(e['status'][key]) for e in functional) == manifest[field] == 182
    assert all(int(e['status']['http-failed']) == int(e['status']['udp-failed']) == 0 for e in functional)
    controls = [e for e in events if e['kind'] in ('invalid-import-control', 'vpn-off-negative-control')]
    assert len(controls) == 4 and all(e['passed'] for e in controls)
    rows = manifest['resourceRows'] if followup else [e for e in manifest['resources'] if e['runId'] == 'all-cipher-diagnostic']
    assert len(rows) == 12
    total_http = total_udp = failures = 0
    for row in rows:
        cycles = [e for e in events if e['kind'] == 'resource-cycle' and e.get('runId') == 'all-cipher-diagnostic' and e['case'] == row['case'] and e['backend'] == row['backend']]
        assert len(cycles) == 2
        for cycle in cycles:
            assert abs((cycle['after']['cpuTicks'] - cycle['before']['cpuTicks']) / 100 - cycle['cpuSeconds']) < 1e-8
            completion = cycle['completion']
            assert completion['httpPassed'] + completion['httpFailed'] == 240
            assert completion['udpPassed'] + completion['udpFailed'] == 480
            total_http += completion['httpPassed']
            total_udp += completion['udpPassed']
            failures += completion['udpFailed']
        for kind in ('httpPassed', 'httpFailed', 'udpPassed', 'udpFailed'):
            field = kind if followup else 'stress' + kind[0].upper() + kind[1:]
            assert row[field] == sum(c['completion'][kind] for c in cycles)
        recovery = next(e for e in events if e['kind'] == 'resource-recovery' and e.get('runId') == 'all-cipher-diagnostic' and e['case'] == row['case'] and e['backend'] == row['backend'])
        limits = manifest['limits']
        passed = recovery['rssGrowthBytes'] <= max(limits['rssGrowthBytes'], recovery['rss'][0] * limits['rssGrowthFraction']) and recovery['threadGrowth'] <= limits['threadGrowth']
        assert passed == recovery['passed'] == row['resourcePassed']
    if not followup:
        assert total_http == 5760 and total_udp == 11518 and failures == 2
    print(root.name, {'functionalCases': 14, 'stressHttpPassed': total_http, 'stressUdpPassed': total_udp, 'stressUdpFailed': failures, 'resourceRowsPassed': sum(r['resourcePassed'] for r in rows)})
    return manifest


baseline = check_report(ROOT, False)
followup = check_report(ROOT / 'packet-pump-fix', True)
a = read_json(ROOT / 'build-identity.json')
b = read_json(ROOT / 'packet-pump-fix/build-identity.json')
assert a['nativeSha256'] == b['nativeSha256'] and a['jniSha256'] == b['jniSha256']
before = {x['path']:x['sha256'] for x in a['sourceHashes']}
after = {x['path']:x['sha256'] for x in b['sourceHashes']}
changed = [key for key, value in before.items() if after[key] != value]
assert changed == ['platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayVpnService.kt'], changed
assert followup['cleanup']['complete']
assert not baseline['releaseAcceptanceComplete'] and not followup['releaseAcceptanceComplete']
print('Hashes, APK source delta, event aggregates and cleanup verified; release acceptance remains open.')
