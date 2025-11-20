# Log Parser for Arbor Peakflow Detection Events

🔍 Notes

Ensure logs follow the Arbor Peakflow format.
Script ignores files without matching patterns.
If no data is found, the CSV will still be created but empty.

**Last Updated:** 2025-11-20  

## Release Notes
- Added input/output folder support.
- Auto-create folders if missing.
- Timestamped CSV output.
- Fixed Stop Time capture logic.


## 📌 Overview
This Python script parses Arbor Peakflow detection logs and extracts attack event details into a structured CSV file. It processes all `.txt` or `.log` files in an input folder and saves the output in an output folder with a timestamped filename.

---

## ✅ Features
- Reads multiple log files from an **input folder**.
- Extracts:
  - Start Time (UTC)
  - Stop Time (UTC)
  - Duration (sec)
  - Destination IP
  - External ID
  - Protected Object
  - Protocol
  - Bandwidth (bps)
- Creates **input** and **output** folders if they don’t exist.
- Exports results as a **CSV file with timestamp**.

---

## 📂 Folder Structure

```Shell
DF-detection-log-parser/
│
├── input_logs/        # Place your log files here
├── output_csv/        # Generated CSV files will be saved here
└── DF-detection-log-parser.py

---

## ⚙️ Requirements
- Python 3.8 or higher
- Install dependencies:
```bash
pip install pandas

## ▶️ Usage Instructions
1. Prepare Input Folder

Create a folder named input_logs in the project directory.
Place all your .txt or .log files containing Arbor Peakflow detection logs inside this folder.

2. Run the Script
```bash
python DF-detection-log-parser.py


3. Output
The script will create an output_csv folder if it doesn’t exist.
It will generate a CSV file named:
```Shell
attack_events_YYYYMMDD_HHMMSS.csv


## 🔍 Notes

Ensure logs follow the Arbor Peakflow format.
Script ignores files without matching patterns.
If no data is found, the CSV will still be created but empty.
