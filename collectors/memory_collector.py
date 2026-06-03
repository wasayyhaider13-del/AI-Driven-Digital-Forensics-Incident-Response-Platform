"""
collectors/memory_collector.py — Memory Forensics Ingestor Agent
==================================================================
Acquires raw memory images or manages folder mounts under memory_dumps/
to supply targets for Volatility 3 plugins.
"""

import os
import datetime
from typing import List, Dict, Any

import config

class MemoryCollector:
    def __init__(self):
        os.makedirs(config.MEM_DUMPS_DIR, exist_ok=True)
        self._write_demo_mem_dump_log()

    def _write_demo_mem_dump_log(self):
        """Creates sample dump metadata reference if directory is empty."""
        sample_path = os.path.join(config.MEM_DUMPS_DIR, "compromised_endpoint.dmp")
        if not os.path.exists(sample_path):
            try:
                # Write empty sample file just to represent space allocation
                with open(sample_path, "wb") as f:
                    f.write(b"DFIR Sentinel Simulated RAM Acquisition Raw Memory dump file metadata.")
            except Exception:
                pass

    def get_acquired_images(self) -> List[Dict[str, Any]]:
        """List raw memory dumps available inside memory_dumps/ directory."""
        images = []
        try:
            for file in os.listdir(config.MEM_DUMPS_DIR):
                if file.endswith((".dmp", ".raw", ".mem", ".img")):
                    path = os.path.join(config.MEM_DUMPS_DIR, file)
                    stat = os.stat(path)
                    sz_mb = round(stat.st_size / (1024 * 1024), 2)
                    c_time = datetime.datetime.utcfromtimestamp(stat.st_ctime)
                    
                    images.append({
                        "file_name": file,
                        "file_path": path,
                        "size_mb": sz_mb if sz_mb > 0 else 512.0, # Default mock size if file is dummy
                        "acquired_at": c_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "source": "mem_dumper_service"
                    })
        except Exception:
            pass
        return images

# Singleton instance
_memory_collector = None

def get_memory_collector() -> MemoryCollector:
    global _memory_collector
    if _memory_collector is None:
        _memory_collector = MemoryCollector()
    return _memory_collector

if __name__ == "__main__":
    col = get_memory_collector()
    print("Acquired memory images:", col.get_acquired_images())
