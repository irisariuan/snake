#!/bin/sh
# Installs (or re-installs) snake's page in the Merlin WebUI "Addons" menu.
# Follows the Asuswrt-Merlin Addons API. Called with: mount.sh <asp-source>
ASP_SRC="$1"
TITLE="snake"
if [ ! -r /usr/sbin/helper.sh ] || ! grep -q '^am_get_webui_page()' /usr/sbin/helper.sh; then
  echo "snake: firmware does not support the Addons API" >&2
  exit 1
fi
. /usr/sbin/helper.sh

# Wait for the web server lock used by other addons.
i=0
while [ -f /tmp/addonwebui.lock ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
touch /tmp/addonwebui.lock

# Reuse our existing page slot if we already have one.
am_webui_page=""
for f in /www/user/user*.asp; do
  [ -f "$f" ] || continue
  if grep -q "snake: split tunnelling" "$f" 2>/dev/null; then am_webui_page="$(basename "$f")"; break; fi
done
if [ -z "$am_webui_page" ]; then
  am_get_webui_page "$ASP_SRC"
fi
if [ "$am_webui_page" = "none" ] || [ -z "$am_webui_page" ]; then
  rm -f /tmp/addonwebui.lock
  echo "snake: no free Addons page slot" >&2
  exit 1
fi

sed "s/{{PAGE}}/$am_webui_page/g" "$ASP_SRC" > "/www/user/$am_webui_page"

if [ ! -f /tmp/menuTree.js ]; then
  cp /www/require/modules/menuTree.js /tmp/
  mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js
fi
sed -i "/url: \"$am_webui_page\", tabName: \"$TITLE\"/d" /tmp/menuTree.js
if grep -q "shared-jy/redirect.htm" /tmp/menuTree.js; then
  # An "Addons" menu exists (created by other addons): put snake there.
  sed -i "/url: \"javascript:var helpwindow=window.open('\/ext\/shared-jy\/redirect.htm'/i {url: \"$am_webui_page\", tabName: \"$TITLE\"}," /tmp/menuTree.js
else
  # Otherwise add it to the Tools menu.
  sed -i "/url: \"Tools_OtherSettings.asp\", tabName:/a {url: \"$am_webui_page\", tabName: \"$TITLE\"}," /tmp/menuTree.js
fi
umount /www/require/modules/menuTree.js 2>/dev/null
mount -o bind /tmp/menuTree.js /www/require/modules/menuTree.js

rm -f /tmp/addonwebui.lock
echo "$am_webui_page"
