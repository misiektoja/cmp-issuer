#!/usr/bin/env bash
#
# Restores the configured EJBCA state into the persistence directory and then hands over to the
# stock start script.
#
# The upstream image declares /mnt/persistent as a volume, which every container runtime replaces with
# empty storage of its own. The configured database and the generated TLS keystore therefore travel in
# the image as an archive outside that path and are unpacked on first start.
set -euo pipefail

SEED_ARCHIVE=/opt/keyfactor/cmp-issuer-e2e/persistent.tar
PERSISTENT_DIR=/mnt/persistent

if [ -f "${PERSISTENT_DIR}/ejbcadb.mv.db" ]; then
    echo "cmp-issuer-e2e: persistent state already present, keeping it"
else
    echo "cmp-issuer-e2e: restoring the configured state into ${PERSISTENT_DIR}"
    # The archive is rooted at a directory entry describing the persistence directory itself. That
    # directory already exists and belongs to another user, so its own metadata is dropped rather than
    # restored, which is what strip-components does here. Ownership is dropped for the same reason:
    # the application runs as an unprivileged user that cannot give a file away.
    tar -xf "${SEED_ARCHIVE}" -C "${PERSISTENT_DIR}" --strip-components=1 --no-same-owner
fi

exec /opt/keyfactor/bin/start.sh "$@"
