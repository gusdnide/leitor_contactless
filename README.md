# Leitor Script

This repository contains a Python script for extracting and processing NFC card data using a smart card reader. The script interacts with NFC cards, parses TLV data, and generates outputs in JSON format.

## Features

- Connects to NFC card readers.
- Extracts AIDs and application data from NFC cards.
- Processes AFL and generates ARQC.
- Parses TLV data and extracts specific tags.
- Saves extracted data to JSON files.

## Requirements

- Python 3.7 or higher
- `pyscard` library for smart card communication
- A compatible NFC card reader

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/gusdnide/leitor_contactless.git
   cd leitor_script
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Connect your NFC card reader to your computer.
2. Run the script:
   ```bash
   python extrair_nfc.py
   ```
3. Follow the on-screen instructions to interact with the NFC card.

## Output

The script saves the extracted data in the `dumps` directory as JSON files. Each file is named based on the card's track2 data and AID.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This script is for educational purposes only. Ensure you have permission to access and process NFC card data.
