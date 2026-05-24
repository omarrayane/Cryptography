# -*- coding: utf-8 -*-
import re
from pathlib import Path

root = Path('.')

summary = []
for path in root.rglob('*.py'):
    text = path.read_text(encoding='utf-8')
    lines = text.splitlines()
    new_lines = []
    removed = 0
    for line in lines:
        s = line.strip()
        if not s.startswith('#'):
            new_lines.append(line)
            continue
        body = s[1:].strip()
        if not body or re.fullmatch(r'[=\-_*\s]+', body):
            removed += 1
            continue
        if len(body.split()) <= 8 and body.endswith(':'):
            removed += 1
            continue
        if len(body.split()) <= 7 and body.upper() == body:
            removed += 1
            continue
        new_lines.append(line)
    if removed:
        path.write_text('\n'.join(new_lines) + '\n', encoding='utf-8')
        summary.append((path, removed))

print('Fichiers modifiés:', len(summary))
for p, r in summary:
    print(f'{p}: {r} commentaires supprimés')
