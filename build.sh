#!/bin/sh
# SPDX-License-Identifier: MIT
# Build-Check: listet Fehler/Warnungen kompakt (Datei(Zeile): Meldung)
cd "$(dirname "$0")"
dotnet build Vitrine.sln -nologo "-clp:NoSummary;ForceNoAlign" > /tmp/vitrine-build.log 2>&1
python3 - <<'PY'
import re
seen=set()
for l in open('/tmp/vitrine-build.log'):
    m=re.search(r'src/(.*?\(\d+,\d+\)): (error|warning) (\w+): (.*?) \[', l)
    if m:
        k=(m.group(1),m.group(3),m.group(4))
        if k not in seen:
            seen.add(k); print(f"{m.group(2)[0].upper()} {m.group(1)} {m.group(3)}: {m.group(4)[:200]}")
t=open('/tmp/vitrine-build.log').read()
ok=' error ' not in t and 'Build FAILED' not in t
print('BUILD OK' if ok else 'BUILD FAILED')
PY
