#!/bin/sh
set -eu

kind=${1:-}
db_file=${2:-}
key_file=${3:-}
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
if [ "${OPENFLUX_RESTORE_CONFIRM:-}" != YES ]; then
  echo "Set OPENFLUX_RESTORE_CONFIRM=YES after verifying the matching database/key pair." >&2
  exit 2
fi
case "$kind" in sqlite|postgres) ;; *) echo "usage: restore.sh sqlite|postgres DB_BACKUP KEY_BACKUP" >&2; exit 2 ;; esac
if [ -z "$db_file" ] || [ -z "$key_file" ]; then
  echo "usage: restore.sh sqlite|postgres DB_BACKUP KEY_BACKUP" >&2
  exit 2
fi
case "$db_file$key_file" in *[!A-Za-z0-9._-]*) echo "Backup arguments must be plain filenames." >&2; exit 2 ;; esac
backup_dir=${OPENFLUX_BACKUP_DIR:-"$root/deploy/compose/backups"}
if [ ! -d "$backup_dir" ]; then echo "Backup directory does not exist." >&2; exit 2; fi
backup_dir=$(CDPATH= cd -- "$backup_dir" && pwd)
OPENFLUX_BACKUP_DIR=$backup_dir
export OPENFLUX_BACKUP_DIR
for file in "$db_file" "$key_file"; do
  if [ ! -f "$backup_dir/$file" ] || [ -L "$backup_dir/$file" ] || [ ! -s "$backup_dir/$file" ]; then
    echo "Backup file is missing, empty, or not a regular file." >&2
    exit 2
  fi
done
case "$db_file" in openflux-*.sqlite3|openflux-*.dump) ;; *) echo "Database backup filename is invalid." >&2; exit 2 ;; esac
case "$key_file" in installation-*.key) ;; *) echo "Installation-key backup filename is invalid." >&2; exit 2 ;; esac
db_stamp=$(printf '%s' "$db_file" | sed 's/^openflux-//; s/\.sqlite3$//; s/\.dump$//')
key_stamp=$(printf '%s' "$key_file" | sed 's/^installation-//; s/\.key$//')
if [ "$db_stamp" != "$key_stamp" ]; then
  echo "Database and installation-key backups must have the same timestamp." >&2
  exit 2
fi
if [ "$(wc -c < "$backup_dir/$key_file" | tr -d ' ')" != 32 ]; then
  echo "Installation-key backup must contain exactly 32 bytes." >&2
  exit 2
fi
compose() {
  if [ "$kind" = postgres ]; then
    docker compose --project-directory "$root" -f "$root/deploy/compose/docker-compose.yml" -f "$root/deploy/compose/docker-compose.postgres.yml" "$@"
  else
    docker compose --project-directory "$root" -f "$root/deploy/compose/docker-compose.yml" "$@"
  fi
}
postgres_compose() { compose "$@"; }
case "$kind" in
  sqlite)
    case "$db_file" in *.sqlite3) ;; *) echo "SQLite backup must use the .sqlite3 extension." >&2; exit 2 ;; esac
    compose run --rm -T --no-deps --user 0 --entrypoint sqlite3 openflux-control "/backup/$db_file" "PRAGMA integrity_check;" | grep -qx ok
    ;;
  postgres)
    case "$db_file" in *.dump) ;; *) echo "PostgreSQL backup must use the .dump extension." >&2; exit 2 ;; esac
    cat "$backup_dir/$db_file" | postgres_compose exec -T postgres pg_restore --list >/dev/null
    ;;
esac
if [ "${OPENFLUX_INSTALLATION_KEY:-}" != "" ]; then
  echo "Unset OPENFLUX_INSTALLATION_KEY so the restored key file is used." >&2
  exit 2
fi

# Preserve the current state before replacing data.
"$root/deploy/scripts/backup.sh" "$kind"
compose stop openflux-panel openflux-control
stopped=1
restart_services() {
  compose up -d openflux-control openflux-panel >/dev/null
  stopped=0
}
cleanup() {
  status=$?
  if [ "$stopped" = 1 ]; then
    if [ "$status" = 0 ]; then
      restart_services >/dev/null 2>&1 || true
    else
      echo "Restore failed; Control and panel remain stopped. The pre-restore backup is in $backup_dir." >&2
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
restore_stamp=$(date -u +%Y%m%dT%H%M%SZ)-$$
if [ "$kind" = sqlite ]; then
  compose run --rm -T --no-deps --user 0 -e RESTORE_DB_FILE="$db_file" -e RESTORE_KEY_FILE="$key_file" -e RESTORE_STAMP="$restore_stamp" --entrypoint /bin/sh openflux-control -ec '
    rm -f /data/.restore.db /data/.restore.db-wal /data/.restore.db-shm
    sqlite3 /data/.restore.db ".restore '\''/backup/$RESTORE_DB_FILE'\''"
    test "$(sqlite3 /data/.restore.db "PRAGMA integrity_check;")" = ok
    cp /data/installation.key "/data/installation.key.pre-restore-$RESTORE_STAMP"
    cp "/backup/$RESTORE_KEY_FILE" /data/.installation.key.restore
    chmod 600 /data/.installation.key.restore "/data/installation.key.pre-restore-$RESTORE_STAMP" /data/.restore.db
    chown 10001:10001 /data/.installation.key.restore "/data/installation.key.pre-restore-$RESTORE_STAMP" /data/.restore.db
    if [ -e /data/openflux-control.db ]; then mv /data/openflux-control.db "/data/openflux-control.db.pre-restore-$RESTORE_STAMP"
    fi
    rm -f /data/openflux-control.db-wal /data/openflux-control.db-shm
    mv /data/.restore.db /data/openflux-control.db
    mv /data/.installation.key.restore /data/installation.key
  '
else
  compose run --rm -T --no-deps --user 0 -e RESTORE_KEY_FILE="$key_file" -e RESTORE_STAMP="$restore_stamp" --entrypoint /bin/sh openflux-control -ec '
    cp /data/installation.key "/data/installation.key.pre-restore-$RESTORE_STAMP"
    cp "/backup/$RESTORE_KEY_FILE" /data/.installation.key.restore
    chmod 600 /data/.installation.key.restore "/data/installation.key.pre-restore-$RESTORE_STAMP"
    chown 10001:10001 /data/.installation.key.restore "/data/installation.key.pre-restore-$RESTORE_STAMP"
  '
  cat "$backup_dir/$db_file" | postgres_compose exec -T postgres pg_restore --clean --if-exists --no-owner --no-acl -U openflux -d openflux
  compose run --rm -T --no-deps --user 0 --entrypoint /bin/sh openflux-control -ec 'mv /data/.installation.key.restore /data/installation.key'
fi
restart_services
trap - EXIT
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if compose exec -T openflux-control wget -q -O - http://127.0.0.1:8787/healthz >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
if [ "$ready" != 1 ]; then echo "Restored services did not become healthy; inspect Compose logs." >&2; exit 1; fi
if [ "$kind" = sqlite ]; then
  printf "Restore completed (sqlite); pre-restore backup created, and the previous DB and key are kept in the volume.\n"
else
  printf "Restore completed (postgres); pre-restore database and key were backed up before replacement.\n"
fi
