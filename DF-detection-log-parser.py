import os
import re
import pandas as pd
from datetime import datetime

# Define input and output folders
input_folder = "input_logs"
output_folder = "output_reports"

# Create folders if they don't exist
os.makedirs(input_folder, exist_ok=True)
os.makedirs(output_folder, exist_ok=True)

# Regex patterns (more flexible)
start_stop_pattern = re.compile(r"start ([0-9\-: ]+) UTC, duration (\d+), stop ([0-9\-: ]+) UTC")
event_pattern = re.compile(r"network ([0-9\.]+)/32 protocol (\w+) external ID (\d+) bandwidth (\d+)\(bps\).*?Protected object ([A-Z\-0-9]+)")

# Initialize list for parsed data
parsed_data = []

# Iterate through all files in input folder
for filename in os.listdir(input_folder):
    if filename.endswith(".txt") or filename.endswith(".log"):
        file_path = os.path.join(input_folder, filename)
        print(f"Processing file: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Split into blocks and parse
        for block in content.split("Additional:"):
            m = start_stop_pattern.search(block)
            event_match = event_pattern.search(block)
            if m and event_match:
                start, duration, stop = m.groups()
                ip, protocol, ext_id, bandwidth, obj = event_match.groups()
                parsed_data.append([start, stop, duration, ip, ext_id, obj, protocol, bandwidth])
            else:
                # Debug: show unmatched blocks
                if "start" in block or "network" in block:
                    print(f"Skipped block (pattern mismatch): {block[:200]}...")

# Create DataFrame
df = pd.DataFrame(parsed_data, columns=[
    "Start Time (UTC)", "Stop Time (UTC)", "Duration (sec)",
    "Destination IP", "External ID", "Protected Object", "Protocol", "Bandwidth (bps)"
])

# Generate timestamped filename
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = os.path.join(output_folder, f"attack_events_{timestamp}.csv")

# Save to CSV
df.to_csv(output_file, index=False)

print(f"Parsing complete. {len(parsed_data)} records saved to: {output_file}")