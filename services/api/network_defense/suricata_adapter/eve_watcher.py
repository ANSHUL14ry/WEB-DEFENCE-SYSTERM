"""
AEGIS Ω — Real-time Suricata EVE JSON Log Watcher Task (Phase 11)
Tails /var/log/suricata/eve.json asynchronously and ingests events into the AEGIS pipeline.
Gracefully handles missing files without crashing.
"""

import asyncio
import json
import logging
import os
from network_defense.network_parser.parser import parse_eve_record
from network_defense.config import netdef_settings
from database import SessionLocal

logger = logging.getLogger("aegis.network_defense.watcher")


async def start_suricata_eve_watcher():
    """Background async worker tailing Suricata EVE JSON file."""
    eve_path = netdef_settings.SURICATA_EVE_LOG_PATH
    logger.info(f"Checking Suricata EVE JSON log path: {eve_path}")

    # Avoid cyclic imports
    from network_defense.service import process_incoming_network_event

    current_file_pos = 0
    while True:
        try:
            if not os.path.exists(eve_path):
                await asyncio.sleep(5)
                continue

            with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(current_file_pos)
                line = f.readline()
                while line:
                    line_str = line.strip()
                    if line_str:
                        try:
                            record = json.loads(line_str)
                            norm_event = parse_eve_record(record, sensor_name=netdef_settings.SURICATA_SENSOR_NAME)
                            if norm_event:
                                db = SessionLocal()
                                try:
                                    await process_incoming_network_event(norm_event, db)
                                finally:
                                    db.close()
                        except json.JSONDecodeError:
                            pass
                        except Exception as e:
                            logger.error(f"Error processing Suricata EVE line: {e}")
                    current_file_pos = f.tell()
                    line = f.readline()

            await asyncio.sleep(1)
        except asyncio.CancelledError:
            logger.info("Suricata EVE watcher task cancelled.")
            break
        except Exception as err:
            logger.warning(f"Suricata EVE watcher error: {err}")
            await asyncio.sleep(5)
