#!/bin/sh
# Removes snake's page from the Merlin WebUI.
TITLE="snake"
i=0
while [ -f /tmp/addonwebui.lock ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
touch /tmp/addonwebui.lock
for f in /www/user/user*.asp; do
  [ -f "$f" ] || continue
  if grep -q "snake: split tunnelling" "$f" 2>/dev/null; then
    page="$(basename "$f")"
    rm -f "$f"
    if [ -f /tmp/menuTree.js ]; then
      sed -i "/url: \"$page\", tabName: \"$TITLE\"/d" /tmp/menuTree.js
      umount /www/require/modules/menuTree.js 2>/dev/null
      mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js
    fi
  fi
done
rm -f /tmp/addonwebui.lock
