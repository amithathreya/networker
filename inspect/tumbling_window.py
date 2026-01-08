import json
import math
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WINDOW_SIZE = 5  # seconds
OUTPUT_TUMBLING_WINDOWS_FILE = "data/window/tumbling_windows.json"


class TumblingWindow:
    """
       Tumbling window aggregator for packet infos and flow states.

       - Windows are fixed-size time buckets keyed by an integer index derived from timestamp_epoch.
       - Each window tracks:
           - start_time_epoch and
    end_time_epoch bounds
           - all packet infos falling into the window
           - a mapping of flow_key -> list of packet infos occurring in the window
    """

    def __init__(self, window_size: int = WINDOW_SIZE):
        # Ensure window_size is an int (avoid accidental tuple by trailing comma)
        self.window_size: int = int(window_size)
        # Windows keyed by integer window index
        self.windows: Dict[int, Dict[str, Any]] = defaultdict(
            lambda: {
                "start_time": None,  # epoch seconds (float)
                "end_time": None,  # epoch seconds (float)
                "packets": [],  # list of packet info dicts
                "flows": defaultdict(list),  # flow_key -> list[packet info]
            }
        )

    def get_window_key(self, timestamp_epoch: float) -> int:
        """
        Compute the window index for the given epoch timestamp.

        Window index is floor(timestamp / window_size):
        - Window 0 covers [0, window_size)
        - Window 1 covers [window_size, 2*window_size), etc.
        """
        if timestamp_epoch < 0:
            # Clamp negative timestamps (shouldn't happen, but be defensive)
            timestamp_epoch = 0.0
        return int(math.floor(timestamp_epoch / self.window_size))

    def _ensure_window_bounds(self, index: int):
        """
        Initialize the start and end time bounds for a window if not set.
        """
        win = self.windows[index]
        if win["start_time"] is None or win["end_time"] is None:
            start_epoch = index * self.window_size
            end_epoch = (index + 1) * self.window_size
            win["start_time"] = float(start_epoch)
            win["end_time"] = float(end_epoch)

    def add_packet(
        self, packet_info: Dict[str, Any], flow_key: Optional[Tuple[Any, ...]]
    ):
        """
        Add a packet info to the appropriate window and associate it with the flow_key.

        packet_info must contain "timestamp_epoch".
        flow_key may be None for packets without IP layer; those packets still get recorded
        in the window's packet list but not in a specific flow mapping.
        """
        ts = float(packet_info.get("timestamp_epoch", 0.0))
        index = self.get_window_key(ts)

        self._ensure_window_bounds(index)
        win = self.windows[index]

        # Record packet
        win["packets"].append(packet_info)

        # Record flow if present
        if flow_key is not None:
            win["flows"][flow_key].append(packet_info)

        # Adjust window bounds defensively using actual packet time
        if win["start_time"] is None or ts < win["start_time"]:
            win["start_time"] = ts
        if win["end_time"] is None or ts > win["end_time"]:
            # end_time should represent the upper bound of the window,
            # but ensure it's not less than the latest packet ts
            theoretical_end = (index + 1) * self.window_size
            win["end_time"] = float(max(theoretical_end, ts))

    def to_serializable(self) -> List[Dict[str, Any]]:
        """
        Convert internal window structure to a JSON-serializable list of windows
        sorted by window_index. Flow keys (tuples) are converted to strings.
        """
        serialized: List[Dict[str, Any]] = []
        for index in sorted(self.windows.keys()):
            win = self.windows[index]

            # Convert flow keys to strings for JSON
            flows_serialized: Dict[str, List[Dict[str, Any]]] = {}
            for fk, pkts in win["flows"].items():
                flows_serialized[str(fk)] = pkts

            start_epoch = float(
                win["start_time"]
                if win["start_time"] is not None
                else index * self.window_size
            )
            end_epoch = float(
                win["end_time"]
                if win["end_time"] is not None
                else (index + 1) * self.window_size
            )

            serialized.append(
                {
                    "window_index": index,
                    "start_time_epoch": start_epoch,
                    "end_time_epoch": end_epoch,
                    "start_time_utc": datetime.fromtimestamp(
                        start_epoch, tz=timezone.utc
                    ).isoformat(),
                    "end_time_utc": datetime.fromtimestamp(
                        end_epoch, tz=timezone.utc
                    ).isoformat(),
                    "packet_count": len(win["packets"]),
                    "flow_count": len(flows_serialized),
                    "packets": win["packets"],
                    "flows": flows_serialized,
                }
            )
        return serialized

    def dump_json(self, filename: str = OUTPUT_TUMBLING_WINDOWS_FILE):
        """
        Dump the tumbling windows data structure to a JSON file.
        Includes window metadata and flow state information for packets per window.
        """
        data = self.to_serializable()
        try:
            Path(filename).parent.mkdir(parents=True, exist_ok=True)
            with open(filename, "w+") as f:
                json.dump(data, f, indent=4)
            print(f"Tumbling window data saved to {filename}")
        except IOError as e:
            print(f"Error writing tumbling window data to {filename}: {e}")
