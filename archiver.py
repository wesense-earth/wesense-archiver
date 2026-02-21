"""
WeSense Archiver — IPFS archive service.

Exports signed readings from ClickHouse, verifies signatures, creates
deterministic Parquet archives with trust snapshots and signed manifests,
uploads to IPFS via wesense-orbitdb, and submits attestations.

One archive per country per day. Gap-aware: on each cycle, checks the IPFS
tree for already-archived dates, compares against ClickHouse, and fills gaps.
"""

import base64
import hashlib
import json
import logging
import os
import shutil
import signal
import sys
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import schedule

logger = logging.getLogger("wesense-archiver")

try:
    import clickhouse_connect

    _CH_AVAILABLE = True
except ImportError:
    _CH_AVAILABLE = False

try:
    from wesense_ingester.signing.keys import IngesterKeyManager, KeyConfig
    from wesense_ingester.signing.trust import TrustStore
    from wesense_ingester.ids.reading_id import generate_reading_id

    _SIGNING_AVAILABLE = True
except ImportError:
    _SIGNING_AVAILABLE = False

try:
    from wesense_ingester.registry.client import RegistryClient
    from wesense_ingester.registry.config import RegistryConfig

    _REGISTRY_AVAILABLE = True
except ImportError:
    _REGISTRY_AVAILABLE = False

# HTTP helpers for archive upload (uses stdlib urllib)
import urllib.error
import urllib.request


@dataclass
class ArchiverConfig:
    """Archiver configuration from environment variables."""

    # ClickHouse
    ch_host: str = "localhost"
    ch_port: int = 8123
    ch_user: str = "wesense"
    ch_password: str = ""
    ch_database: str = "wesense"

    # Signing
    key_dir: str = "data/keys"

    # Trust
    trust_file: str = "data/trust_list.json"

    # OrbitDB
    orbitdb_url: str = "http://wesense-orbitdb:5200"

    # Staging
    staging_dir: str = "data/staging"

    # Schedule interval (hours)
    interval_hours: int = 4

    # Regions (empty = all)
    regions: list = None

    # Earliest date to archive (None = use earliest ClickHouse data)
    start_date: str | None = None

    @classmethod
    def from_env(cls) -> "ArchiverConfig":
        regions_str = os.getenv("ARCHIVE_REGIONS", "")
        regions = [r.strip() for r in regions_str.split(",") if r.strip()] if regions_str else None

        start_date_str = os.getenv("ARCHIVE_START_DATE", "").strip()

        return cls(
            ch_host=os.getenv("CLICKHOUSE_HOST", "localhost"),
            ch_port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
            ch_user=os.getenv("CLICKHOUSE_USER", "wesense"),
            ch_password=os.getenv("CLICKHOUSE_PASSWORD", ""),
            ch_database=os.getenv("CLICKHOUSE_DATABASE", "wesense"),
            key_dir=os.getenv("ZENOH_KEY_DIR", "data/keys"),
            trust_file=os.getenv("TRUST_FILE", "data/trust_list.json"),
            orbitdb_url=os.getenv("ORBITDB_URL", "http://wesense-orbitdb:5200"),
            staging_dir=os.getenv("ARCHIVE_STAGING_DIR", "data/staging"),
            interval_hours=int(os.getenv("ARCHIVE_INTERVAL_HOURS", "4")),
            regions=regions,
            start_date=start_date_str if start_date_str else None,
        )


class WeSenseArchiver:
    """Exports signed readings from ClickHouse, creates verifiable IPFS archives."""

    def __init__(self, config: ArchiverConfig):
        self.config = config
        self._ch_client = None
        self._key_manager = None
        self._trust_store = None

    def _connect_clickhouse(self):
        """Establish ClickHouse connection."""
        if not _CH_AVAILABLE:
            raise RuntimeError("clickhouse-connect not installed")

        self._ch_client = clickhouse_connect.get_client(
            host=self.config.ch_host,
            port=self.config.ch_port,
            username=self.config.ch_user,
            password=self.config.ch_password,
            database=self.config.ch_database,
        )
        logger.info(
            "Connected to ClickHouse at %s:%d/%s",
            self.config.ch_host,
            self.config.ch_port,
            self.config.ch_database,
        )

    def _init_signing(self):
        """Load or generate archiver Ed25519 keypair."""
        if not _SIGNING_AVAILABLE:
            raise RuntimeError("wesense-ingester-core signing not available")

        key_config = KeyConfig(key_dir=self.config.key_dir)
        self._key_manager = IngesterKeyManager(config=key_config)
        self._key_manager.load_or_generate()
        logger.info("Archiver identity: %s (version %d)", self._key_manager.ingester_id, self._key_manager.key_version)

    def _init_trust(self):
        """Load the trust store."""
        if not _SIGNING_AVAILABLE:
            raise RuntimeError("wesense-ingester-core signing not available")

        self._trust_store = TrustStore(trust_file=self.config.trust_file)

        # Sync trust from OrbitDB if available
        if _REGISTRY_AVAILABLE:
            try:
                reg_config = RegistryConfig(
                    url=self.config.orbitdb_url,
                    enabled=True,
                    sync_interval=3600,
                )
                client = RegistryClient(config=reg_config, trust_store=self._trust_store)
                client.sync_trust_once()
                logger.info("Trust store synced from OrbitDB")
            except Exception as e:
                logger.warning("Failed to sync trust from OrbitDB: %s", e)

    def start(self):
        """Initialize connections and start the archiver."""
        self._connect_clickhouse()
        self._init_signing()
        self._init_trust()
        logger.info("Archiver initialized successfully")

    def _check_orbitdb(self) -> bool:
        """Check if the OrbitDB service is reachable."""
        url = f"{self.config.orbitdb_url.rstrip('/')}/health"
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            return False

    def archive_cycle(self):
        """Run a gap-aware archive cycle.

        1. Check OrbitDB is reachable
        2. Query ClickHouse for countries with signed readings
        3. For each country, get the actual dates with data
        4. Subtract already-archived dates from the IPFS tree
        5. Archive any missing dates (oldest first)
        """
        logger.info("Starting archive cycle...")

        if not self._check_orbitdb():
            logger.warning("OrbitDB unreachable at %s — skipping cycle", self.config.orbitdb_url)
            return

        # Don't archive today — incomplete data would change readings_hash
        yesterday = datetime.now(timezone.utc).date() - timedelta(days=1)

        # Clamp start to configured start_date if set
        start_date = None
        if self.config.start_date:
            start_date = date.fromisoformat(self.config.start_date)

        # Get all countries with signed data
        countries = self._get_countries_with_data(start_date, yesterday)
        if self.config.regions:
            countries = [c for c in countries if c in self.config.regions]

        if not countries:
            logger.info("No countries with signed readings to archive")
            return

        logger.info("Countries with signed data: %s", ", ".join(countries))

        for country in countries:
            # Query only the dates that actually have data for this country
            data_dates = self._get_dates_with_data(country, start_date, yesterday)
            if not data_dates:
                continue

            archived = self._get_archived_dates(country)
            missing = sorted(data_dates - archived)

            if not missing:
                logger.info("%s: fully archived (%d days)", country, len(data_dates))
                continue

            logger.info("%s: %d to archive of %d total days", country, len(missing), len(data_dates))

            for i, period in enumerate(missing, 1):
                try:
                    self.archive_period(period, country)
                    logger.info("%s: archived %d/%d (%s)", country, i, len(missing), period)
                except Exception as e:
                    logger.error("Failed to archive %s/%s: %s", period, country, e, exc_info=True)

        logger.info("Archive cycle complete")

    def _get_countries_with_data(self, start: date | None, end: date) -> list[str]:
        """Get list of countries with signed local readings."""
        conditions = ["signature != ''", "received_via = 'local'", "toDate(timestamp) <= {end:String}"]
        params = {"end": end.isoformat()}
        if start:
            conditions.append("toDate(timestamp) >= {start:String}")
            params["start"] = start.isoformat()

        query = f"""
            SELECT DISTINCT geo_country
            FROM sensor_readings
            WHERE {' AND '.join(conditions)}
            ORDER BY geo_country
        """
        result = self._ch_client.query(query, parameters=params)
        return [row[0] for row in result.result_rows if row[0]]

    def _get_dates_with_data(self, country: str, start: date | None, end: date) -> set[str]:
        """Get the actual dates that have signed readings for a country."""
        conditions = [
            "signature != ''",
            "received_via = 'local'",
            "geo_country = {country:String}",
            "toDate(timestamp) <= {end:String}",
        ]
        params = {"country": country, "end": end.isoformat()}
        if start:
            conditions.append("toDate(timestamp) >= {start:String}")
            params["start"] = start.isoformat()

        query = f"""
            SELECT DISTINCT toDate(timestamp) as d
            FROM sensor_readings
            WHERE {' AND '.join(conditions)}
            ORDER BY d
        """
        result = self._ch_client.query(query, parameters=params)
        dates = set()
        for row in result.result_rows:
            d = row[0]
            if isinstance(d, date):
                dates.add(d.isoformat())
            else:
                dates.add(str(d))
        return dates

    def _get_archived_dates(self, country: str) -> set[str]:
        """Check the IPFS tree for already-archived dates for a country.

        Walks /{country}/{year}/{month}/{day}/ and returns a set of ISO date strings.
        Returns empty set if OrbitDB is unreachable or tree is empty.
        """
        archived = set()
        base_url = f"{self.config.orbitdb_url.rstrip('/')}/archives/tree"

        try:
            # List years: GET /archives/tree/{country}
            years = self._list_tree_entries(f"{base_url}/{country}")
            for year_entry in years:
                year = year_entry["name"]
                # List months: GET /archives/tree/{country}/{year}
                months = self._list_tree_entries(f"{base_url}/{country}/{year}")
                for month_entry in months:
                    month = month_entry["name"]
                    # List days: GET /archives/tree/{country}/{year}/{month}
                    days = self._list_tree_entries(f"{base_url}/{country}/{year}/{month}")
                    for day_entry in days:
                        day = day_entry["name"]
                        archived.add(f"{year}-{month}-{day}")
        except Exception as e:
            logger.warning("Failed to query IPFS tree for %s: %s — will re-archive all", country, e)
            return set()

        if archived:
            logger.debug("%s: %d dates already archived in IPFS tree", country, len(archived))
        return archived

    def _list_tree_entries(self, url: str) -> list[dict]:
        """Fetch directory entries from a tree URL. Returns entries with 'name' and 'type'."""
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            return [e for e in data.get("entries", []) if e.get("type") == "directory"]

    def archive_period(self, period: str, region: str) -> dict:
        """
        Archive a single country/day.

        1. Query ClickHouse for signed readings
        2. Verify each signature against trust store
        3. Build trust snapshot
        4. Export deterministic Parquet
        5. Compute readings_hash
        6. Build and sign manifest
        7. Write to staging directory
        8. Upload via POST /archives on wesense-orbitdb
        9. Submit attestation to OrbitDB

        Returns the manifest dict.
        """
        logger.info("Archiving %s/%s", region, period)

        # 1. Query signed readings
        readings = self._query_readings(period, region)
        if not readings:
            logger.info("No signed readings for %s/%s — skipping", region, period)
            return None

        logger.info("Fetched %d signed readings for %s/%s", len(readings), region, period)

        # 2. Verify signatures
        verified, failed = self._verify_signatures(readings)
        logger.info(
            "Signature verification: %d verified, %d failed for %s/%s",
            len(verified),
            failed,
            region,
            period,
        )

        if not verified:
            logger.warning("No verified readings for %s/%s — skipping", region, period)
            return None

        # 3. Build trust snapshot
        ingester_ids = set()
        for r in verified:
            if r.get("ingester_id"):
                ingester_ids.add(r["ingester_id"])
        trust_snapshot = self._build_trust_snapshot(ingester_ids)

        # 4. Export Parquet (deterministic: sorted by reading_id, zstd compression)
        parquet_bytes = self._export_parquet(verified)

        # 5. Compute readings_hash
        reading_ids = sorted([r["reading_id"] for r in verified if r.get("reading_id")])
        readings_hash = self._compute_readings_hash(reading_ids)

        # 6. Build and sign manifest
        trust_snapshot_json = json.dumps(trust_snapshot, sort_keys=True, indent=2)
        trust_snapshot_hash = hashlib.sha256(trust_snapshot_json.encode()).hexdigest()

        manifest = {
            "version": 1,
            "period": period,
            "region": region,
            "reading_count": len(verified),
            "readings_hash": readings_hash,
            "trust_snapshot_hash": trust_snapshot_hash,
            "signatures_verified": len(verified),
            "signatures_failed": failed,
            "archiver_id": self._key_manager.ingester_id,
            "created": datetime.now(timezone.utc).isoformat(),
        }

        # Sign the manifest
        manifest_content = json.dumps(
            {k: v for k, v in manifest.items() if k != "archiver_signature"},
            sort_keys=True,
        ).encode()
        signature = self._key_manager.private_key.sign(manifest_content)
        manifest["archiver_signature"] = signature.hex()

        # 7. Write to staging directory
        date_parts = period.split("-")
        staging_path = Path(self.config.staging_dir) / region / date_parts[0] / date_parts[1] / date_parts[2]

        # Clean staging path if it exists
        if staging_path.exists():
            shutil.rmtree(staging_path)
        staging_path.mkdir(parents=True, exist_ok=True)

        # Write files
        (staging_path / "readings.parquet").write_bytes(parquet_bytes)
        (staging_path / "trust_snapshot.json").write_text(trust_snapshot_json)
        manifest_json = json.dumps(manifest, indent=2)
        (staging_path / "manifest.json").write_text(manifest_json)

        logger.info(
            "Staged archive at %s (readings: %d, hash: %s...)",
            staging_path,
            len(verified),
            readings_hash[:16],
        )

        # 8. Upload via POST /archives
        archive_cid = self._upload_to_ipfs()

        if archive_cid:
            manifest["archive_cid"] = archive_cid
            # Re-write manifest with CID
            manifest_json = json.dumps(manifest, indent=2)
            (staging_path / "manifest.json").write_text(manifest_json)

        # 9. Submit attestation
        self._submit_attestation(manifest, readings_hash)

        logger.info(
            "Archive complete for %s/%s — CID: %s, readings_hash: %s",
            region,
            period,
            archive_cid or "upload-pending",
            readings_hash[:16],
        )

        # Clean staging directory after successful upload
        if archive_cid:
            shutil.rmtree(staging_path, ignore_errors=True)

        return manifest

    def _query_readings(self, period: str, region: str) -> list[dict]:
        """Query ClickHouse for signed readings for a country/day."""
        query = """
            SELECT
                device_id,
                timestamp,
                reading_type,
                value,
                unit,
                latitude,
                longitude,
                altitude,
                geo_country,
                geo_subdivision,
                data_source,
                board_model,
                node_name,
                transport_type,
                ingester_id,
                key_version,
                signature
            FROM sensor_readings FINAL
            WHERE toDate(timestamp) = {period:String}
              AND geo_country = {region:String}
              AND signature != ''
              AND received_via = 'local'
            ORDER BY device_id, reading_type, timestamp
        """
        result = self._ch_client.query(query, parameters={"period": period, "region": region})

        columns = [
            "device_id", "timestamp", "reading_type", "value",
            "unit", "latitude", "longitude", "altitude", "geo_country",
            "geo_subdivision", "data_source", "board_model", "node_name",
            "transport_type", "ingester_id", "key_version", "signature",
        ]

        readings = []
        for row in result.result_rows:
            reading = dict(zip(columns, row))
            # Preserve unix timestamp for signature verification and reading_id
            ts = reading["timestamp"]
            if hasattr(ts, "timestamp"):
                reading["_ts_unix"] = int(ts.timestamp())
                reading["timestamp"] = ts.isoformat()
            else:
                reading["_ts_unix"] = int(datetime.fromisoformat(str(ts)).timestamp())
            reading["reading_id"] = generate_reading_id(
                reading["device_id"], reading["_ts_unix"], reading["reading_type"], reading["value"]
            )
            readings.append(reading)

        return readings

    def _verify_signatures(self, readings: list[dict]) -> tuple[list[dict], int]:
        """
        Verify Ed25519 signatures on readings.

        Returns (verified_readings, failed_count).
        """
        verified = []
        failed = 0

        for reading in readings:
            ingester_id = reading.get("ingester_id", "")
            key_version = reading.get("key_version", 0)
            signature_hex = reading.get("signature", "")

            if not ingester_id or not signature_hex:
                failed += 1
                continue

            public_key = self._trust_store.get_public_key(ingester_id, key_version)
            if public_key is None:
                # Unknown ingester — count as not verifiable but still include
                # (trust store may be incomplete)
                logger.debug(
                    "No trusted key for %s v%d — including reading without verification",
                    ingester_id,
                    key_version,
                )
                verified.append(reading)
                continue

            # Reconstruct the exact payload that was signed by the ingester:
            # same 8 fields, with timestamp as unix int, sorted keys
            payload_dict = {
                "data_source": reading.get("data_source", ""),
                "device_id": reading["device_id"],
                "latitude": reading["latitude"],
                "longitude": reading["longitude"],
                "reading_type": reading["reading_type"],
                "timestamp": reading["_ts_unix"],
                "transport_type": reading.get("transport_type", ""),
                "value": reading["value"],
            }
            payload = json.dumps(payload_dict, sort_keys=True).encode()

            try:
                signature_bytes = bytes.fromhex(signature_hex)
                public_key.verify(signature_bytes, payload)
                verified.append(reading)
            except Exception:
                failed += 1
                logger.debug("Signature verification failed for reading %s (ingester=%s)", reading.get("reading_id", "?"), ingester_id)

        return verified, failed

    def _build_trust_snapshot(self, ingester_ids: set[str]) -> dict:
        """Build a trust snapshot containing only keys referenced in the batch."""
        snapshot = self._trust_store.export_snapshot(list(ingester_ids))
        snapshot["snapshot_time"] = datetime.now(timezone.utc).isoformat()
        return snapshot

    def _export_parquet(self, readings: list[dict]) -> bytes:
        """
        Export readings to a deterministic Parquet file.

        Determinism is achieved by:
        - Sorting by reading_id (content-based hash, deterministic)
        - Using zstd compression (deterministic for same input)
        - Fixed schema with explicit column types
        """
        # Sort by reading_id for deterministic output
        readings_sorted = sorted(readings, key=lambda r: r.get("reading_id", ""))

        schema = pa.schema([
            ("reading_id", pa.string()),
            ("device_id", pa.string()),
            ("timestamp", pa.string()),
            ("reading_type", pa.string()),
            ("value", pa.float64()),
            ("unit", pa.string()),
            ("latitude", pa.float64()),
            ("longitude", pa.float64()),
            ("altitude", pa.float64()),
            ("geo_country", pa.string()),
            ("geo_subdivision", pa.string()),
            ("data_source", pa.string()),
            ("board_model", pa.string()),
            ("node_name", pa.string()),
            ("transport_type", pa.string()),
            ("ingester_id", pa.string()),
            ("key_version", pa.uint32()),
            ("signature", pa.string()),
        ])

        # Build column arrays
        columns = {}
        for field in schema:
            col_name = field.name
            if field.type == pa.float64():
                columns[col_name] = [float(r.get(col_name, 0) or 0) for r in readings_sorted]
            elif field.type == pa.uint32():
                columns[col_name] = [int(r.get(col_name, 0) or 0) for r in readings_sorted]
            else:
                columns[col_name] = [str(r.get(col_name, "") or "") for r in readings_sorted]

        table = pa.table(columns, schema=schema)

        # Write to bytes buffer
        import io
        buf = io.BytesIO()
        pq.write_table(
            table,
            buf,
            compression="zstd",
            use_dictionary=False,
            write_statistics=False,
        )
        return buf.getvalue()

    def _compute_readings_hash(self, reading_ids: list[str]) -> str:
        """
        Compute deterministic readings_hash.

        1. Sort reading_ids lexicographically (already sorted by caller)
        2. Concatenate all IDs
        3. SHA-256 hash the concatenation
        """
        concatenated = "".join(reading_ids)
        return hashlib.sha256(concatenated.encode()).hexdigest()

    def _upload_to_ipfs(self) -> str | None:
        """Upload staging directory to IPFS via POST /archives on wesense-orbitdb."""
        url = f"{self.config.orbitdb_url.rstrip('/')}/archives"
        data = json.dumps({"staging_dir": self.config.staging_dir}).encode()
        headers = {"Content-Type": "application/json"}

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode())
                if result.get("ok"):
                    cid = result.get("root_cid", "")
                    logger.info("IPFS upload successful — root CID: %s", cid)
                    return cid
                else:
                    logger.error("IPFS upload failed: %s", result)
                    return None
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
            logger.error("IPFS upload failed: %s", e)
            return None

    def _submit_attestation(self, manifest: dict, readings_hash: str):
        """Submit attestation to OrbitDB via PUT /attestations/:readings_hash."""
        url = f"{self.config.orbitdb_url.rstrip('/')}/attestations/{readings_hash}"
        attestation = {
            "ingester_id": manifest.get("archiver_id", ""),
            "signature": manifest.get("archiver_signature", ""),
            "readings_hash": readings_hash,
            "archive_cid": manifest.get("archive_cid", ""),
            "period": manifest.get("period", ""),
            "region": manifest.get("region", ""),
            "reading_count": manifest.get("reading_count", 0),
            "signatures_verified": manifest.get("signatures_verified", 0),
            "signatures_failed": manifest.get("signatures_failed", 0),
        }

        data = json.dumps(attestation).encode()
        headers = {"Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data, headers=headers, method="PUT")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
                logger.info(
                    "Attestation submitted for %s — count: %d",
                    readings_hash[:16],
                    result.get("attestation_count", 0),
                )
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
            logger.error("Attestation submission failed: %s", e)


def setup_logging():
    """Configure logging."""
    level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


def main():
    setup_logging()
    logger.info("WeSense Archiver starting...")

    config = ArchiverConfig.from_env()
    archiver = WeSenseArchiver(config)

    # Initialize connections
    try:
        archiver.start()
    except Exception as e:
        logger.error("Failed to initialize archiver: %s", e, exc_info=True)
        sys.exit(1)

    # Graceful shutdown
    stop = False

    def handle_signal(signum, frame):
        nonlocal stop
        logger.info("Received signal %d, shutting down...", signum)
        stop = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Always run a cycle on startup (gap-aware, so safe to repeat)
    logger.info("Running initial archive cycle...")
    try:
        archiver.archive_cycle()
    except Exception as e:
        logger.error("Initial archive cycle failed: %s", e, exc_info=True)

    # Schedule recurring cycles
    schedule.every(config.interval_hours).hours.do(archiver.archive_cycle)
    logger.info("Scheduled archive every %d hours", config.interval_hours)

    # Run loop
    while not stop:
        schedule.run_pending()
        time.sleep(60)

    logger.info("Archiver stopped")


if __name__ == "__main__":
    main()
