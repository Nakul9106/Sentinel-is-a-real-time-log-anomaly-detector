"""Log file ingestion and real-time tailing engine for Sentinel.

Reliably tails log files across platforms (including Windows file locking,
rotation, truncation, and deferred file creation).
"""

from __future__ import annotations

import io
import logging
import os
import time
from collections.abc import Generator
from pathlib import Path
from typing import Optional

logger = logging.getLogger("sentinel.ingestor")


class LogIngestor:
    """Real-time log file follower with rotation, truncation, and Windows file lock resilience."""

    def __init__(
        self,
        file_path: Path | str,
        poll_interval: float = 0.1,
        from_start: bool = False,
    ) -> None:
        self.file_path = Path(file_path)
        self.poll_interval = max(0.01, poll_interval)
        self.from_start = from_start
        self._stop_requested: bool = False
        self.lines_read_count: int = 0
        self.rotations_detected: int = 0
        self.truncations_detected: int = 0

    def stop(self) -> None:
        """Signal the tail loop to terminate cleanly."""
        self._stop_requested = True

    def _open_file(self) -> Optional[io.TextIOWrapper]:
        """Safely opens the target file on Windows/POSIX with shared access and retries."""
        for attempt in range(5):
            if not self.file_path.exists():
                return None
            try:
                # Open with utf-8, replace bad chars, buffered
                return open(self.file_path, "r", encoding="utf-8", errors="replace")
            except (PermissionError, OSError) as err:
                # Windows file locking contention: wait briefly and retry
                time.sleep(0.05 * (attempt + 1))
            except Exception as err:
                logger.warning(f"Error opening '{self.file_path}': {err}")
                return None
        return None

    def tail(self) -> Generator[str, None, None]:
        """Generator yielding new lines appended to the monitored file in real time.

        Handles:
        - Waiting for file creation if initially missing
        - Seeking to end by default (or start if from_start=True)
        - Truncation (seeking back to 0)
        - File replacement / rotation (re-opening new file)
        - Windows file sharing retry
        - Clean termination via stop() or KeyboardInterrupt
        """
        self._stop_requested = False

        # 1. Wait for file to exist if not present yet
        while not self._stop_requested and not self.file_path.exists():
            time.sleep(self.poll_interval)

        if self._stop_requested:
            return

        file_obj = self._open_file()
        while not self._stop_requested and file_obj is None:
            time.sleep(self.poll_interval)
            file_obj = self._open_file()

        if self._stop_requested or file_obj is None:
            return

        try:
            # 2. Position cursor
            if not self.from_start:
                file_obj.seek(0, os.SEEK_END)
            else:
                file_obj.seek(0, os.SEEK_SET)

            last_inode = self._get_file_identifier()
            last_size = self._get_file_size()

            while not self._stop_requested:
                line = file_obj.readline()

                if line:
                    self.lines_read_count += 1
                    yield line
                    continue

                # No new line; perform health checks: truncation & rotation
                time.sleep(self.poll_interval)

                # Check if file was rotated or replaced
                current_inode = self._get_file_identifier()
                if current_inode is not None and current_inode != last_inode:
                    # File was replaced / rotated!
                    self.rotations_detected += 1
                    logger.info(f"Log rotation detected for '{self.file_path}'. Switching to new file.")
                    try:
                        file_obj.close()
                    except Exception:
                        pass

                    new_obj = self._open_file()
                    if new_obj is not None:
                        file_obj = new_obj
                        file_obj.seek(0, os.SEEK_SET)
                        last_inode = self._get_file_identifier()
                        last_size = self._get_file_size()
                    continue

                # Check if file was truncated (copytruncate)
                current_size = self._get_file_size()
                if current_size is not None and current_size < file_obj.tell():
                    self.truncations_detected += 1
                    logger.info(f"Log truncation detected for '{self.file_path}'. Resetting offset to 0.")
                    file_obj.seek(0, os.SEEK_SET)
                    last_size = current_size
                    continue

                last_size = current_size

        except GeneratorExit:
            pass
        except KeyboardInterrupt:
            pass
        finally:
            if file_obj:
                try:
                    file_obj.close()
                except Exception:
                    pass

    def _get_file_size(self) -> Optional[int]:
        """Returns file size in bytes, or None if inaccessible."""
        try:
            return self.file_path.stat().st_size
        except (OSError, FileNotFoundError):
            return None

    def _get_file_identifier(self) -> Optional[tuple[int, float]]:
        """Returns unique file identity (stat ino, mtime, or size) to detect rotation."""
        try:
            st = self.file_path.stat()
            # On Windows st_ino may be 0, so combine st_ino and st_ctime
            return (st.st_ino, st.st_ctime)
        except (OSError, FileNotFoundError):
            return None
