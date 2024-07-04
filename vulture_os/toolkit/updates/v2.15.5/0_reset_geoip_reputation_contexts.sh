#!/usr/bin/env sh

if /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py is_node_bootstrapped >/dev/null 2>&1; then
    /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py shell -c 'from applications.reputation_ctx.models import ReputationContext; ReputationContext.objects.filter(db_type="GeoIP").delete()'
    /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py loaddata reputation_ctx
fi