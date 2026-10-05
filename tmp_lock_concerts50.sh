#!/bin/bash
set -e

CONF='/etc/nginx/conf.d/concerts50.app.jday.in.ua.conf'
BACKUP="/etc/nginx/conf.d/concerts50.app.jday.in.ua.conf.bak.$(date +%F_%H%M%S)"

sudo cp -a "$CONF" "$BACKUP"

sudo perl -0pi -e 's/(include \/etc\/nginx\/conf.d\/concerts50-maintenance-state.inc;\n)/$1    if (\$concerts50_is_internal = 0) {\n        return 404;\n    }\n/s' "$CONF"
sudo perl -0pi -e 's/server \{\n    if \(\$host = concerts50\.app\.jday\.in\.ua\) \{/server {\n    if (\$concerts50_is_internal = 0) {\n        return 404;\n    }\n    if (\$host = concerts50.app.jday.in.ua) {/s' "$CONF"

sudo nginx -t
sudo systemctl reload nginx

printf '=== HTTPS ===\n'
curl -k -I -H 'Host: concerts50.app.jday.in.ua' https://127.0.0.1/ | head -n 5
printf '=== HTTP ===\n'
curl -I -H 'Host: concerts50.app.jday.in.ua' http://127.0.0.1/ | head -n 5
