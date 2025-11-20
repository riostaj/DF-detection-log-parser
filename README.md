
# Log Parser for Arbor Peakflow Detection Events

## Overview
This Python script parses raw detection event logs from Arbor Peakflow (or similar DDoS detection systems) and extracts key fields into a structured CSV file. It creates input and output folders automatically and saves the parsed data with a timestamped filename.

---

## Features
- Reads a `.txt` file from `input_logs/` folder.
- Extracts:
  - **Start Time (UTC)**
  - **Stop Time (UTC)**
  - **Duration (sec)**
  - **Destination IP**
  - **External ID**
  - **Protected Object**
  - **Protocol**
  - **Bandwidth (bps)**
- Creates `input_logs/` and `output_reports/` folders if they don't exist.
- Outputs a **CSV file** with a timestamped filename in `output_reports/`.

---

## Requirements
- Python 3.x

---

## Installation
1. Clone or download this repository.
2. Place your log file (`logs.txt`) inside the `input_logs` folder.
3. Ensure Python is installed on your system.

---

## Usage
Run the script:
```bash
python parse_logs.py