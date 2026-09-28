#!/usr/bin/env python3
"""Split an .mbox export (e.g. Google Takeout) into individual .eml files.

Usage: python3 tools/split_mbox.py Spam.mbox spam_eml
"""
import mailbox
import pathlib
import sys

if len(sys.argv) < 2:
    sys.exit("Usage: python3 tools/split_mbox.py <file.mbox> [output_dir]")

src = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "spam_eml")
if not src.is_file():
    sys.exit(f"[!] File not found: {src}")
if src.stat().st_size == 0:
    sys.exit(f"[!] {src} is empty (0 bytes)")

out.mkdir(exist_ok=True)
count = 0
for i, msg in enumerate(mailbox.mbox(src, create=False)):
    (out / f"msg_{i:05}.eml").write_bytes(msg.as_bytes())
    count += 1
print(f"Saved {count} emails to {out}/")
