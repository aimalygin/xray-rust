#!/usr/bin/env python3
"""Render one fixed workload slice; the report retains all 70 cases."""
import argparse
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('report', type=Path)
a = p.parse_args()
summary = json.loads((a.report / 'data/summary-mac-3pct.json').read_text())
rows = {r['case']: r for r in summary['rows']}
profiles = ['trojan-tls', 'ss2022-aes128', 'ss2022-aes256', 'ss2022-chacha20',
            'vmess-aes128', 'vmess-chacha20', 'vmess-auto']
labels = ['Trojan\nTLS', 'SS2022\nAES-128', 'SS2022\nAES-256', 'SS2022\nChaCha20',
          'VMess\nAES-128', 'VMess\nChaCha20', 'VMess\nauto']
clients = [('candidate', 'xray-rust', '#cc5c30'), ('xray', 'Xray-core', '#7755aa'),
           ('singbox', 'sing-box', '#17847e')]
fig, axes = plt.subplots(3, 1, figsize=(12, 10), sharex=True, layout='constrained')
metrics = [('throughput_mib_s', 'Throughput · MiB/s · higher is better', 1),
           ('rss_mib', 'Sampled client RSS · MiB · lower is better', 1),
           ('cpu_ms_per_mib', 'Client CPU · ms/GiB · lower is better', 1024)]
x = np.arange(len(profiles))
for ax, (metric, title, scale) in zip(axes, metrics):
    for index, (client, label, color) in enumerate(clients):
        values = [rows[name + '-socks-download-8']['versions'][client]['metrics'].get(metric)
                  for name in profiles]
        if any(v is None for v in values):
            raise ValueError('cannot chart an incomplete client group')
        med = np.array([v['median'] * scale for v in values])
        low = np.array([v['min'] * scale for v in values])
        high = np.array([v['max'] * scale for v in values])
        ax.bar(x + (index - 1) * .25, med, .23, label=label, color=color,
               yerr=[med - low, high - med], capsize=2, error_kw={'elinewidth': .7})
    ax.set_title(title, loc='left', fontsize=11)
    ax.set_ylim(bottom=0)
    ax.grid(axis='y', alpha=.18)
    ax.set_axisbelow(True)
    ax.spines[['top', 'right']].set_visible(False)
axes[0].legend(loc='upper right', frameon=False, ncol=3)
axes[-1].set_xticks(x, labels)
fig.suptitle('v0.8 protocols — eight-flow TCP download\n'
             '256 MiB/flow · medians and min/max of 5 trials · Apple M3 Pro, macOS 26.6.2',
             fontsize=14)
fig.savefig(a.report / 'download-8.svg')
fig.savefig(a.report / 'download-8.png', dpi=160)
