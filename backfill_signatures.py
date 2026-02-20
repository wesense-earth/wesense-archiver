"""
Backfill signatures for historical unsigned readings.

Retroactively signs local readings that were ingested before Ed25519 signing
was deployed. Uses the archiver's own key to attest that this station
ingested the data.

Runs inside the archiver container:
    docker exec wesense-archiver python backfill_signatures.py

Safe to re-run — only updates rows where signature = ''.
"""

import argparse
import json
import logging
import os
import sys
from datetime import date, datetime, timedelta, timezone

import clickhouse_connect
from wesense_ingester.signing.keys import IngesterKeyManager, KeyConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [backfill] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("backfill")

# All columns in sensor_readings, in schema order
ALL_COLUMNS = [
    "timestamp", "device_id", "data_source", "network_source", "ingestion_node_id",
    "reading_type", "value", "unit", "sample_count", "sample_interval_avg",
    "value_min", "value_max", "latitude", "longitude", "altitude",
    "geo_country", "geo_subdivision", "geo_h3_res8", "sensor_model", "board_model",
    "calibration_status", "data_quality_flag", "deployment_type", "transport_type",
    "location_source", "firmware_version", "deployment_location", "node_name",
    "deployment_type_source", "node_info", "node_info_url",
    "signature", "ingester_id", "key_version", "received_via",
]

# Indices of signature fields in ALL_COLUMNS
IDX_SIGNATURE = ALL_COLUMNS.index("signature")
IDX_INGESTER_ID = ALL_COLUMNS.index("ingester_id")
IDX_KEY_VERSION = ALL_COLUMNS.index("key_version")

# Indices of fields needed for signing payload
IDX_TIMESTAMP = ALL_COLUMNS.index("timestamp")
IDX_DEVICE_ID = ALL_COLUMNS.index("device_id")
IDX_DATA_SOURCE = ALL_COLUMNS.index("data_source")
IDX_READING_TYPE = ALL_COLUMNS.index("reading_type")
IDX_VALUE = ALL_COLUMNS.index("value")
IDX_LATITUDE = ALL_COLUMNS.index("latitude")
IDX_LONGITUDE = ALL_COLUMNS.index("longitude")
IDX_TRANSPORT_TYPE = ALL_COLUMNS.index("transport_type")


def sign_row(row, private_key):
    """Compute Ed25519 signature for a reading row.

    Reconstructs the exact 8-field signing payload used by all ingesters.
    """
    ts = row[IDX_TIMESTAMP]
    if hasattr(ts, "timestamp"):
        ts_unix = int(ts.timestamp())
    else:
        ts_unix = int(datetime.fromisoformat(str(ts)).timestamp())

    payload_dict = {
        "data_source": row[IDX_DATA_SOURCE],
        "device_id": row[IDX_DEVICE_ID],
        "latitude": row[IDX_LATITUDE],
        "longitude": row[IDX_LONGITUDE],
        "reading_type": row[IDX_READING_TYPE],
        "timestamp": ts_unix,
        "transport_type": row[IDX_TRANSPORT_TYPE],
        "value": row[IDX_VALUE],
    }
    payload = json.dumps(payload_dict, sort_keys=True).encode()
    signature = private_key.sign(payload)
    return signature.hex()


def get_date_range(client):
    """Get the date range of unsigned local readings."""
    result = client.query("""
        SELECT min(toDate(timestamp)), max(toDate(timestamp))
        FROM sensor_readings
        WHERE signature = '' AND received_via = 'local'
    """)
    if not result.result_rows or result.result_rows[0][0] is None:
        return None
    row = result.result_rows[0]
    start = row[0] if isinstance(row[0], date) else date.fromisoformat(str(row[0]))
    end = row[1] if isinstance(row[1], date) else date.fromisoformat(str(row[1]))
    return start, end


def backfill_day(client, day, private_key, ingester_id, key_version):
    """Sign and re-insert all unsigned local readings for a single day."""
    day_str = day.isoformat()

    columns_sql = ", ".join(ALL_COLUMNS)
    result = client.query(f"""
        SELECT {columns_sql}
        FROM sensor_readings
        WHERE toDate(timestamp) = {{day:String}}
          AND signature = ''
          AND received_via = 'local'
    """, parameters={"day": day_str})

    rows = result.result_rows
    if not rows:
        return 0

    signed_rows = []
    for row in rows:
        row = list(row)
        sig_hex = sign_row(row, private_key)
        row[IDX_SIGNATURE] = sig_hex
        row[IDX_INGESTER_ID] = ingester_id
        row[IDX_KEY_VERSION] = key_version
        signed_rows.append(row)

    client.insert("sensor_readings", signed_rows, column_names=ALL_COLUMNS)
    return len(signed_rows)


def main():
    parser = argparse.ArgumentParser(description="Backfill Ed25519 signatures for historical readings")
    parser.add_argument("--start-date", help="Start date (YYYY-MM-DD), default: earliest unsigned")
    parser.add_argument("--end-date", help="End date (YYYY-MM-DD), default: yesterday")
    parser.add_argument("--key-dir", default=os.environ.get("KEY_DIR", "/app/data/keys"),
                        help="Directory containing ingester_key.pem")
    parser.add_argument("--ch-host", default=os.environ.get("CLICKHOUSE_HOST", "clickhouse"))
    parser.add_argument("--ch-port", type=int, default=int(os.environ.get("CLICKHOUSE_PORT", "8123")))
    parser.add_argument("--ch-user", default=os.environ.get("CLICKHOUSE_USER", "wesense"))
    parser.add_argument("--ch-password", default=os.environ.get("CLICKHOUSE_PASSWORD", ""))
    parser.add_argument("--ch-database", default=os.environ.get("CLICKHOUSE_DATABASE", "wesense"))
    args = parser.parse_args()

    # Load signing key
    config = KeyConfig(key_dir=args.key_dir, key_file="ingester_key.pem")
    key_manager = IngesterKeyManager(config=config)
    key_manager.load_or_generate()
    logger.info("Signing identity: %s (version %d)", key_manager.ingester_id, key_manager.key_version)

    # Connect to ClickHouse
    client = clickhouse_connect.get_client(
        host=args.ch_host,
        port=args.ch_port,
        username=args.ch_user,
        password=args.ch_password,
        database=args.ch_database,
    )
    logger.info("Connected to ClickHouse at %s:%d/%s", args.ch_host, args.ch_port, args.ch_database)

    # Determine date range
    date_range = get_date_range(client)
    if not date_range:
        logger.info("No unsigned local readings found")
        return

    ch_start, ch_end = date_range

    if args.start_date:
        ch_start = max(ch_start, date.fromisoformat(args.start_date))
    if args.end_date:
        ch_end = min(ch_end, date.fromisoformat(args.end_date))

    # Don't sign today — data is still arriving
    yesterday = datetime.now(timezone.utc).date() - timedelta(days=1)
    ch_end = min(ch_end, yesterday)

    if ch_start > ch_end:
        logger.info("No days in range (start=%s, end=%s)", ch_start, ch_end)
        return

    total_days = (ch_end - ch_start).days + 1
    logger.info("Backfilling %s to %s (%d days)", ch_start, ch_end, total_days)

    total_signed = 0
    current = ch_start
    day_num = 0

    while current <= ch_end:
        day_num += 1
        count = backfill_day(client, current, key_manager.private_key, key_manager.ingester_id, key_manager.key_version)
        if count > 0:
            total_signed += count
            logger.info("[%d/%d] %s: signed %d readings (total: %d)", day_num, total_days, current, count, total_signed)
        current += timedelta(days=1)

    logger.info("Backfill complete: %d readings signed across %d days", total_signed, total_days)

    if total_signed > 0:
        logger.info("Running OPTIMIZE to merge signed rows...")
        client.command("OPTIMIZE TABLE sensor_readings FINAL")
        logger.info("Done")


if __name__ == "__main__":
    main()
