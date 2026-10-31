#!/bin/bash
# before against timed on the delayed path, with --cap-add NET_ADMIN: one
# download 8 rounds and eight downloads 4 rounds at about 50 and 113 ms.
set -u
for d in 20 50; do
  /runs/delayed.sh "$d" /runs/rbn.sh 8 /runs/timed-delayed.jsonl none download:1
  /runs/delayed.sh "$d" /runs/rbn.sh 4 /runs/timed-delayed.jsonl none download:8
done
