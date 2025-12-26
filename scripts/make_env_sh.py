#!/usr/bin/env python3
from pathlib import Path
import shlex

p = Path(__file__).resolve().parents[1] / '.env.production'
out = Path('/tmp/sf_env.sh')
if not p.exists():
    raise SystemExit(f"{p} not found")
lines = []
for raw in p.read_text().splitlines():
    s = raw.strip()
    if not s or s.startswith('#') or '=' not in s:
        continue
    k, v = s.split('=', 1)
    v = v.strip()
    # remove inline comments like: 16777216  # 16MB
    if '#' in v:
        v = v.split('#', 1)[0].strip()
    q = shlex.quote(v)
    lines.append(f"export {k}={q}")
out.write_text("\n".join(lines))
print('Wrote', out)
