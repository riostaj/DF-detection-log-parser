import os
import re
import csv
from datetime import datetime

# Define input and output folders
input_folder = "input_logs"
output_folder = "output_reports"

# Create folders if they don't exist
os.makedirs(input_folder, exist_ok=True)
os.makedirs(output_folder, exist_ok=True)

# Input file path
input_file = os.path.join(input_folder, "detection.log")

# Output file path with timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = os.path.join(output_folder, f"parsed_attacks_{timestamp}.csv")

# Regex patterns for extracting fields
main_pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?"
    r"Protected object (?P<object>[^:]+): attack started on network (?P<ip>[\d\.]+)/32 protocol (?P<protocol>[A-Z]+).*?"
    r"external ID (?P<external_id>\d+).*?"
    r"bandwidth (?P<bandwidth>\d+)"
)

additional_pattern = re.compile(
    r"start (?P<start>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC, duration (?P<duration>\d+).*?(stop (?P<stop>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC)?"
)

rows = []
current_event = None

# Check if input file exists
if os.path.exists(input_file):
    with open(input_file, "r") as file:
        for line in file:
            main_match = main_pattern.search(line)
            if main_match:
                current_event = {
                    "Start Time (UTC)": main_match.group("timestamp"),
                    "Stop Time (UTC)": "",
                    "Duration (sec)": "",
                    "Destination IP": main_match.group("ip"),
                    "External ID": main_match.group("external_id"),
                    "Protected Object": main_match.group("object"),
                    "Protocol": main_match.group("protocol"),
                    "Bandwidth (bps)": main_match.group("bandwidth")
                }
                rows.append(current_event)
                continue

            if current_event:
                add_match = additional_pattern.search(line)
                if add_match:
                    # Update Start Time only if empty
                    if not current_event["Start Time (UTC)"]:
                        current_event["Start Time (UTC)"] = add_match.group("start")
                    current_event["Duration (sec)"] = add_match.group("duration")
                    if add_match.group("stop"):
                        current_event["Stop Time (UTC)"] = add_match.group("stop")

    # Write to CSV
    header = [
        "Start Time (UTC)", "Stop Time (UTC)", "Duration (sec)",
        "Destination IP", "External ID", "Protected Object",
        "Protocol", "Bandwidth (bps)"
    ]

    with open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Parsing complete! Data saved to {output_file}")
else:
    print(f"Input file not found. Please place 'logs.txt' inside the '{input_folder}' folder.")