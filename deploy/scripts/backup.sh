#!/bin/sh
set -eu

kind=${1:-sqlite}
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
backup_dir=${OPENFLUX_BACKUP_DIR:-"$root/deploy/compose/backups"}
mkdir -p "$backup_dir"
backup_dir=$(CDPATH= cd -- "$backup_dir" && pwd)
OPENFLUX_BACKUP_DIR=$backup_dir
export OPENFLUX_BACKUP_DIR
chmod 700 "$backup_dir"
umask 077
stamp=$(date -u +%Y%m%dT%H%M%SZ)-$$
db_path="$backup_dir/openflux-$stamp"
tmp_path="$db_path.tmp"
compose() { docker compose --project-directory "$root" -f "$root/deploy/compose/docker-compose.yml" "$@"; }
postgres_compose() { compose -f "$root/deploy/compose/docker-compose.postgres.yml" "$@"; }

case "$kind" in
  sqlite)
    compose exec -T --user 0 openflux-control sh -ec "umask 077; tmp=/tmp/openflux-backup-$stamp.sqlite3; sqlite3 /data/openflux-control.db \".backup \$tmp\"; cat \"\$tmp\"; rm -f \"\$tmp\"" > "$tmp_path"
    chmod 600 "$tmp_path"
    mv "$tmp_path" "$db_path.sqlite3"
    ;;
  postgres)
    postgres_compose exec -T postgres pg_dump -U openflux -d openflux -Fc > "$tmp_path"
    chmod 600 "$tmp_path"
    mv "$tmp_path" "$db_path.dump"
    ;;
  *)
    echo "usage: $0 sqlite|postgres" >&2
    exit 2
    ;;
esac
compose exec -T openflux-control cat /data/installation.key > "$backup_dir/installation-$stamp.key"
chmod 600 "$backup_dir/installation-$stamp.key"
printf 'Backup created: %s (%s)\n' "$stamp" "$kind"
