# Crypto Seed Phrase Generator & Scanner (Tkinter)

A desktop GUI app to generate BIP39 seed phrases, derive a Bitcoin P2PKH address (m/44'/0'/0'/0/0), check balance via Blockstream API, and save any wallets with non‑zero balances. Includes multithreaded auto‑search, bulk scan from a file, live chart, and export to ZIP.

## Features
- Generate 12 or 24 word BIP39 mnemonics.
- Derive Bitcoin P2PKH address using a **minimal BIP32 implementation** at path `m/44'/0'/0'/0/0`.
- Balance check via Blockstream.info API.
- Save found wallets (`> 0` sats, configurable) to:
  - `found_wallets/ADDRESS.txt`
  - `found_wallets.csv` (timestamped rows)
- GUI (Tkinter) with:
  - Dark theme
  - Inputs: 12/24 words, thread count (auto-suggest ~50% of cores), "Only save balance > 0" checkbox
  - Buttons: Generate One, Start Auto Search, Stop, Bulk Scan From File, Export Found as .zip
  - Output window
  - Stats (uptime, total checked, wallets found)
  - Progress bar for bulk scans
  - **Live matplotlib chart**: time (s) vs wallets found (updates from background threads smoothly)
- Multithreading with `ThreadPoolExecutor` for performance.
- Thread-safe GUI updates (Tk `after()` + queue).
- Optional Telegram alert when a non-zero wallet is found (set env vars).

> ⚠️ **Important**: This tool is for educational/research use. Brute forcing valid seed phrases of real wallets is computationally impractical. Do not use on wallets you do not own.

## Requirements
- Python 3.9+ recommended
- Windows/Mac/Linux
- See `requirements.txt`

## Install
```bash
python -m venv .venv
# Windows
.venv\Scripts\pip install -r requirements.txt
# macOS/Linux
source .venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
python crypto_seed_generator.py
```

## Usage
1. Choose 12 or 24 words.
2. Adjust threads (defaults to ~50% of CPU cores). Warnings appear if you exceed core count.
3. (Optional) Keep checked: “Only save wallets with balance > 0”.
4. Click **Start Auto Search** for continuous scanning, **Generate One** to test a single seed, or **Bulk Scan From File** to scan a `.txt` with one mnemonic per line.
5. Results with non-zero balance (or all balances if unchecked) are saved under `found_wallets/` and appended to `found_wallets.csv`.
6. Use **Export Found as .zip** to bundle the `found_wallets/` folder.

### Bulk Scan Format
Plain text file, one seed phrase per line, e.g.:
```
about legal winner thank year wave sausage worth useful legal winner thank yellow
```

## Configuration
- **API**: Uses Blockstream (`https://blockstream.info/api`) by default.
- **Telegram Alerts (optional)**: Set environment variables before launching:
  - `TELEGRAM_BOT_TOKEN=123:abc`
  - `TELEGRAM_CHAT_ID=123456789`
When a wallet is found, the app sends a short alert.

## Build a Portable .exe (Windows)
Using PyInstaller:
```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --name "CryptoSeedScanner" crypto_seed_generator.py
```
The binary will be in the `dist/` folder. If you see missing DLL issues on some systems, try:
```bash
pyinstaller --noconfirm --onefile --windowed --add-data "mnemonic;mnemonic" crypto_seed_generator.py
```

## Notes on Key Derivation
- This app implements a **minimal BIP32** flow to derive the first account address at `m/44'/0'/0'/0/0` from the BIP39 seed. It uses `ecdsa` for secp256k1 operations and `base58` for P2PKH encoding.
- The Blockstream API balance combines confirmed + mempool stats for a quick “current” view.

## CSV Schema (`found_wallets.csv`)
```
timestamp,mnemonic,address,balance_sats,balance_btc,derivation_path
```

## License
MIT
