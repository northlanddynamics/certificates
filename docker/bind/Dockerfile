FROM internetsystemsconsortium/bind9:9.18
COPY named.conf /etc/bind/named.conf
# BIND keeps a journal beside each dynamic zone, so the zone files live in the image, writable by named.
COPY --chown=bind:bind *.test.db /var/cache/bind/
