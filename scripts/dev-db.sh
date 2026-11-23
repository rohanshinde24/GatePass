#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
state="$PWD/.gatepass"
mkdir -p "$state"
chmod 700 "$state"
if [ ! -f "$state/postgres/PG_VERSION" ]; then
  initdb -D "$state/postgres" -A trust -U gatepass --no-instructions >/dev/null
fi
if ! pg_ctl -D "$state/postgres" status >/dev/null 2>&1; then
  pg_ctl -D "$state/postgres" -l "$state/postgres.log" -o "-p 5433 -h 127.0.0.1 -k $state" start
fi
if [ "$(psql -h 127.0.0.1 -p 5433 -U gatepass -d postgres -tAc "SELECT count(*) FROM pg_database WHERE datname='gatepass'")" = "0" ]; then
  createdb -h 127.0.0.1 -p 5433 -U gatepass gatepass
fi
printf '%s\n' 'GatePass development PostgreSQL is ready on loopback port 5433.'
