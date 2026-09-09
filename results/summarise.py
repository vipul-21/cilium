#!/usr/bin/env python3
"""Summarise and compare benchmark arms produced by fqdn-bench.sh.

  ./summarise.py <results-dir> [arm ...]     default: base-60 flag-60
"""
import re, sys, os

def sec(s):
    t = 0.0
    for v, u in re.findall(r'([0-9.]+)(h|ms|m|s|µs|ns)', s):
        t += float(v) * {'h':3600,'m':60,'s':1,'ms':1e-3,'µs':1e-6,'ns':1e-9}[u]
    return t

def load(root, arm):
    d = sorted(sec(l.strip()) for l in open(f'{root}/{arm}/waits.txt') if l.strip())
    n = len(d) or 1
    p = lambda q: d[min(int(n*q), n-1)] if d else 0.0
    rows, hdr = [], []
    for l in open(f'{root}/{arm}/samples.tsv'):
        f = l.split()
        if not f: continue
        if f[0] == 'minute': hdr = f; continue
        rows.append(f)
    last = max(int(r[0]) for r in rows)
    fin = [r for r in rows if int(r[0]) == last]
    col = {name: i for i, name in enumerate(hdr)}
    def grab(name, cast=float):
        i = col.get(name)
        if i is None: return []
        return [cast(r[i]) for r in fin if i < len(r) and r[i] not in ('?', '')]
    return dict(
        arm=arm, n=len(d),
        p50=p(.5), p90=p(.9), p99=p(.99), mx=(d[-1] if d else 0),
        o5=100*sum(1 for x in d if x > 5)/n,
        o10=100*sum(1 for x in d if x > 10)/n,
        o30=sum(1 for x in d if x > 30),
        cache=grab('cache', int), conn=grab('conn', int), gc=grab('gcsec'),
        cli=open(f'{root}/{arm}/clients.txt').read().strip(),
        rows=rows, col=col)

def fmt(v, unit=''):
    if not v: return 'n/a'
    return ' / '.join(('%.2f' % x if isinstance(x, float) else str(x)) for x in v) + unit

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    arms = sys.argv[2:] or ['base-60', 'flag-60']
    a = [load(root, x) for x in arms if os.path.isdir(f'{root}/{x}')]
    if len(a) < 2:
        print('need at least two arms'); return
    w = 20
    print('%-26s' % 'metric' + ''.join('%*s' % (w, x['arm']) for x in a))
    print('-' * (26 + w*len(a)))
    print('%-26s' % 'GC pass duration' + ''.join('%*s' % (w, fmt(x['gc'], 's')) for x in a))
    print('%-26s' % 'cache (final)' + ''.join('%*s' % (w, fmt(x['cache'])) for x in a))
    print('%-26s' % 'zombies (connection)' + ''.join('%*s' % (w, fmt(x['conn'])) for x in a))
    print('-' * (26 + w*len(a)))
    for k, lbl in (('p50','lock wait p50'), ('p90','lock wait p90'),
                   ('p99','lock wait p99'), ('mx','lock wait max')):
        print('%-26s' % lbl + ''.join('%*s' % (w, '%.2fs' % x[k]) for x in a))
    print('%-26s' % 'waits > 5s' + ''.join('%*s' % (w, '%.1f%%' % x['o5']) for x in a))
    print('%-26s' % 'waits > 10s' + ''.join('%*s' % (w, '%.1f%%' % x['o10']) for x in a))
    print('%-26s' % 'waits > 30s' + ''.join('%*s' % (w, str(x['o30'])) for x in a))
    print('%-26s' % 'lock warnings (n)' + ''.join('%*s' % (w, str(x['n'])) for x in a))
    print('-' * (26 + w*len(a)))
    for x in a:
        print('%-12s %s' % (x['arm'], x['cli']))
    # per-minute onset table
    for x in a:
        print('\n=== %s: per-minute ===' % x['arm'])
        c, cl = x['col'], {}
        print('%4s %9s %9s %9s %9s' % ('min','cache','zombies','gc_sec','warns'))
        for r in x['rows']:
            if len(r) <= c.get('conn', 99): continue
            gc = r[c['gcsec']] if 'gcsec' in c and len(r) > c['gcsec'] else '?'
            try: gc = '%.2f' % float(gc)
            except Exception: gc = '?'
            print('%4s %9s %9s %9s %9s' % (r[0], r[c['cache']], r[c['conn']], gc, r[c['lockwarns']]))

main()
