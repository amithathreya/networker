import json
import math
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

WINDOW_SIZE = 5  # seconds
OUTPUT_TUMBLING_WINDOWS_FILE = "data/window/tumbling_windows.json"


class TumblingWindow:

    def __init__(self, window_size: int = WINDOW_SIZE):
        self.window_size: int = int(window_size)
    
        self.windows: Dict[int, Dict[str, Any]] = defaultdict(
            lambda: {
                "start_time": None,  
                "end_time": None,  
                "packets": [],  
                "flows": defaultdict(list),  
                "iat_timestamps": [],
                "last_packet_time": None
            }
        )

    def get_window_key(self, timestamp_epoch: float) -> int:

        if timestamp_epoch < 0:
            
            timestamp_epoch = max(0.0, float(timestamp_epoch))
        return int(math.floor(timestamp_epoch / self.window_size)) * self.window_size

    def _ensure_window_bounds(self, index: int):

        win = self.windows[index]
        if win["start_time"] is None or win["end_time"] is None:
            start_epoch = index * self.window_size
            end_epoch = (index + 1) * self.window_size
            win["start_time"] = float(start_epoch)
            win["end_time"] = float(end_epoch)

    def add_packet(
        self, packet_info: Dict[str, Any], flow_key: Optional[Tuple[Any, ...]]
    ):

        ts = float(packet_info.get("timestamp_epoch", 0.0))
        index = self.get_window_key(ts)

        self._ensure_window_bounds(index)
        win = self.windows[index]

        if win["last_packet_time"] is not None:
            iat = ts - win["last_packet_time"]
            win["iat_timestamps"].append(iat)
        win["last_packet_time"] = ts
        
        win["packets"].append(packet_info)

        if flow_key is not None:
            win["flows"][flow_key].append(packet_info)

        if win["start_time"] is None or ts < win["start_time"]:
            win["start_time"] = ts
        if win["end_time"] is None or ts > win["end_time"]:
            theoretical_end = (index + 1) * self.window_size
            win["end_time"] = float(max(theoretical_end, ts))

    def to_serializable(self) -> List[Dict[str, Any]]:
        serialized: List[Dict[str, Any]] = []
        for index in sorted(self.windows.keys()):
            win = self.windows[index]

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
                    "flows": flows_serialized,
                    "avg_iat_metrics": self.calculate_iat_size(win["iat_timestamps"])
                }
            )
        return serialized

    def dump_json(self, filename: str = OUTPUT_TUMBLING_WINDOWS_FILE):
        data = self.to_serializable()
        try:
            Path(filename).parent.mkdir(parents=True, exist_ok=True)
            with open(filename, "w+") as f:
                json.dump(data, f, indent=4)
            print(f"Tumbling window data saved to {filename}")
        except IOError as e:
            print(f"Error writing tumbling window data to {filename}: {e}")
    
    
    def calculate_iat_size(self,packet_timestamps : List[float])-> dict[str,float]:
        if len(packet_timestamps) < 2:
            return {"mean_iat": 0.0, "iat_entropy": 0.0, "iat_stddev": 0.0}
        iat_values = np.diff(sorted(packet_timestamps))
        return {
            # mean 
            "mean_iat": float(np.mean(iat_values)),
            #shannon entropy calculation
            "iat_entropy": float(-np.sum((np.bincount(iat_values.astype(int)) / len(iat_values)) * np.log2(np.bincount(iat_values.astype(int)) / len(iat_values) + 1e-10))),
            # standard deviation
            "iat_stddev": float(np.std(iat_values)),
            #min and max    
            "iat_min": float(np.min(iat_values)),
            "iat_max"  : float(np.max(iat_values))
        }

    
    def get_window_token(self,window_index:int)-> str:
        win = self.windows[window_index]
        flow_lines = []
    
        for flow_key, packet_list in win["flows"].items():
            # Calculate stats specifically for THIS flow in THIS window
            count = len(packet_list)
            syn_count = sum(1 for p in packet_list if "S" in p.get("flags_str", ""))
            ack_count = sum(1 for p in packet_list if "A" in p.get("flags_str", ""))
            rst_count = sum(1 for p in packet_list if "R" in p.get("flags_str", ""))
            avg_size = sum(p["length"] for p in packet_list) / count
            is_udp = any(p.get("protocol") == 17 for p in packet_list)
            
            # Calculate IAT for this specific flow
            ts = sorted([p["timestamp_epoch"] for p in packet_list])
            iats = [ts[i] - ts[i-1] for i in range(1, len(ts))]
            avg_iat = sum(iats) / len(iats) if iats else 0
            
            # Determine token for this specific flow
            if count == 1:
                token = "SINGLE_PACKET_WINDOW"
            elif syn_count > (count*0.9) and avg_iat < 0.001:
                token = "SYN_FLOOD_ATTACK"
            elif rst_count > (count * 0.5):
                token = "CONNECTION_RESET_SCAN"
            elif is_udp and avg_iat < 0.001:
                token = "UDP_FLOOD_ATTACK"
            
            elif avg_size > 1200 and count > 50:
                token = "POTENTIAL_EXFILTRATION"
            elif avg_iat < 0.001:
                token = "VOLUMETRIC_BURST"
            elif avg_iat > 1.0:
                token = "LOW_FREQUENCY_WINDOW"
            else:
                token = "NORMAL_FLOW"
                
            # Create the combined string
            clean_key = f"{flow_key[0]}_{flow_key[1]}_{flow_key[4]}"
            flow_lines.append(f"{clean_key} {token}")
            
        return flow_lines # type: ignore