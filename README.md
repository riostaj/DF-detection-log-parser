# Log Parser for Arbor Peakflow Detection Events

## Overview

This Python script parses raw detection event logs from Arbor Peakflow (or similar DDoS detection systems) and extracts key fields into a structured CSV file. It is designed to handle logs in the format you provided and produce a clean table for analysis.

---

## Features

- Reads a `.txt` file containing raw logs.
- Extracts:
    - **Start Time (UTC)**
    - **Stop Time (UTC)**
    - **Duration (sec)**
    - **Destination IP**
    - **External ID**
    - **Protected Object**
    - **Protocol**
    - **Bandwidth (bps)**
- Handles multiple entries and ignores irrelevant lines.
- Outputs a **CSV file** with a timestamped filename for easy analysis.

---

## Requirements

- Python 3.x

---

## Installation

1. Clone or download this repository.
2. Place your log file (e.g., `logs.txt`) in the same directory as the script.
3. Ensure Python is installed on your system.

---

## Usage

1. Save your logs in a text file named `logs.txt` (or update the script with your file name).
2. Run the script:

```Shell
python parse_logs.py
```

3. The script will generate a CSV file named like `parsed_attacks_YYYYMMDD_HHMMSS.csv` in the same directory.

---

## Output Format

The CSV file will have the following columns:

|Start Time (UTC)|Stop Time (UTC)|Duration (sec)|Destination IP|External ID|Protected Object|Protocol|Bandwidth (bps)|
|---|---|---|---|---|---|---|---|

Example:

```
2025-11-13 17:29:04,2025-11-13 17:33:59,295,216.208.222.66,10556766,LAC-EDGE-01,OTHER,162940000
```

---

## Log Format Assumptions

- Each detection event starts with a timestamp and contains:
    - `Protected object <name>`
    - `attack started on network <IP>/32`
    - `protocol <PROTOCOL>`
    - `external ID <ID>`
    - `bandwidth <bps>`
- Additional details (stop time, duration) appear in subsequent lines.

---

## Customization

- To include **Impact metrics**, extend the regex and add columns.
- To handle **multiple protocols per event**, modify the regex or append to the `Protocol` field.

---

## Next Steps

- Validate against large log files.
- Add Excel export option if needed.

---

### License

MIT License – Free to use and modify.
