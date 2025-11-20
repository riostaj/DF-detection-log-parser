import os
import re
import pandas as pd
from datetime import datetime

input_folder = "input_logs"
output_folder = "output_csv"

os.makedirs(input_folder, exist_ok=True)
os.makedirs(output_folder, exist_ok=True)

# Regex patterns
event_pattern = re.compile(r"Protected object ([A-Z\\-0-9]+): attack started on network ([0-9\\.]+)/32 protocol (\\w+) external ID (\\d+) bandwidth (\\d+)\\(bps\\)")
additional_pattern = re.compile(r"Host Detection alert #(\\d+), start ([0-9\\-: ]+) UTC, duration (\\d+), stop ([0-9\\-: ]+) UTC")

events = {}
parsed_data = []

# Step 1: Collect detection event details
for filename in os.listdir(input_folder):
    if filename.endswith(".txt") or filename.endswith(".log"):
        file_path = os.path.join(input_folder, filename)
        print(f"Processing file: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Extract detection events
        for match in event_pattern.finditer(content):
            obj, ip, protocol, ext_id, bandwidth = match.groups()
            events[ext_id] = {
                "Destination IP": ip,
                "Protected Object": obj,
                "Protocol": protocol,
                "Bandwidth (bps)": bandwidth
            }

        # Extract Additional info and link by External ID
        for match in additional_pattern.finditer(content):
            ext_id, start, duration, stop = match.groups()
            if ext_id in events:
                data = [
                    start, stop, duration,
                    events[ext_id]["Destination IP"],
                    ext_id,
                    events[ext_id]["Protected Object"],
                    events[ext_id]["Protocol"],
                    events[ext_id]["Bandwidth (bps)"]
                ]
                parsed_data.append(data)

# Create DataFrame
df = pd.DataFrame(parsed_data, columns=[
    "Start Time (UTC)", "Stop Time (UTC)", "Duration (sec)",
    "Destination IP", "External ID", "Protected Object", "Protocol", "Bandwidth (bps)"
])

# Save CSV
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = os.path.join(output_folder, f"attack_events_{timestamp}.csv")
df.to_csv(output_file, index=False)

print(f"Parsing complete. {len(parsed_data)} records saved to: {output_file}")