# Autopsy Phishing Detection Plugin

Comprehensive Autopsy ingest module that extracts URLs from multiple browser sources (Chrome/Edge/Brave/Opera/Chromium, Firefox, Internet Explorer, Safari/Edge Legacy) and prepares them for phishing analysis.

## Features

- Unified ingest module coordinating browser-specific processors
- Extracts from history, bookmarks, downloads, favicons; logs and form data where applicable
- Normalizes timestamps across browsers (Chrome, Firefox, Safari, IE/Edge Legacy)
- Creates artifacts for review in Autopsy Results Viewer
- Generates an HTML summary report with statistics and charts in the case Reports folder
- Modular design for adding new browsers and analysis

## Project Structure

- `phishing_detector_main.py` — Autopsy Ingest Module entry point and coordinator
- `phishing_detector/`
  - `chromium_processor.py` — Chrome/Edge/Brave/Opera/Chromium handler
  - `firefox_processor.py` — Firefox handler
  - `ie_processor.py` — Internet Explorer and generic WebCache handler
  - `safari_edge_processor.py` — Safari and Edge Legacy handlers
  - `artifact_creator.py` — Blackboard artifact creation utilities
  - `browser_constants.py` — File patterns and SQL query constants
  - `report_generator.py` — HTML summary report generator

## Requirements

- Autopsy with Python/Jython ingest support (scripted ingest)
- Java SQLite JDBC driver already available via Autopsy runtime
- No external Python packages are required (module targets the Jython environment inside Autopsy)

## Installation

Place the folder in your Autopsy Python modules directory (this repo already matches that path on Windows):

- Windows: `%AppData%/autopsy/python_modules/autopsy-phishing-detection-plugin`

Ensure the directory contains:

- `phishing_detector_main.py`
- `phishing_detector/` package and its files

Restart Autopsy. The module appears as "Comprehensive URL Phishing Extractor" under Ingest Modules.

## Usage

1. Create/open an Autopsy case and add your data source.
2. In Ingest Modules, enable "Comprehensive URL Phishing Extractor".
3. Run ingest. URLs and related artifacts will appear under the Results tree.
4. A summary HTML report will be generated under Case Reports in a folder named `URL_Phishing_Report`.

## Development

- The code is written for Jython inside Autopsy and uses Java classes via Jython interop.
- Artifacts are created using Autopsy's Blackboard API.
- Browser processors are modular—add new handlers by following the pattern in `phishing_detector/`.

## Packaging (Optional)

If you want to share this as a zip, compress the folder contents and distribute. Autopsy users can unzip into their Autopsy `python_modules` directory.


