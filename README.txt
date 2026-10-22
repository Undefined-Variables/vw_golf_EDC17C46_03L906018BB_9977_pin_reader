ECU PIN READER 1.0
==================
Offline Python reader for the verified Bosch EDC17C46 / 03L906018BB 9977 layout.
Created 21 October 2026.

QUICK START ON WINDOWS
1. Extract the entire ZIP into a folder.
2. Double-click start_reader.bat.
3. Browse to your full ECU backup, then click Read PIN.
4. For separate raw files, choose the EEPROM in the first box and its matching
   flash in the second box. Leave the flash box empty for a full backup.

Requires Python 3.10 or later, with Tcl/Tk for the desktop window. No pip packages,
dongle, Ghidra, internet access or vehicle connection are needed to run the reader.
This ZIP contains source code and a Windows launcher, not a compiled EXE.
You can also drag a full backup file onto start_reader.bat for a console result.

COMMAND LINE
  python ecu_pin_reader.py "my full backup.bin"
  python ecu_pin_reader.py eeprom.bin --flash flash.bin
  python ecu_pin_reader.py "my full backup.bin" --json result.json
  python ecu_pin_reader.py --help

Without arguments the script opens the desktop window. On Linux/macOS, use
python3 instead of python. JSON export only creates new files: choose a different
filename if a report already exists. Exit code 0 means decoding completed;
check the result's status field for verified_offline_backup versus candidate.
Exit code 2 means input, decoding, export or desktop startup failed.

SUPPORTED INPUTS
- The observed full-backup container: 2,162,891 bytes; 203-byte header, XOR
  FE 7F BF 5F aligned to file offset zero, then flash followed by EEPROM.
  The container header's other fields are not interpreted. The decoded firmware
  and records must pass all validation; size alone is never treated as proof.
- A raw combined image: exactly 2,162,688 bytes, 2,097,152 bytes of flash followed
  by 65,536 bytes of EEPROM, without a header or container XOR.
- A separate pair: exactly 65,536 bytes of EEPROM plus 2,097,152 bytes of flash
  from the SAME ECU. The CPU-ID copy in the flash is required to decode the data.

An engine maps-only read is insufficient. An instrument cluster's 8 KB 24C64 dump
is unsupported. Other ECU families, other firmware layouts and other backup
container formats are unsupported. This is not a universal ECU PIN extractor.

HOW RESULTS ARE LABELLED
PIN / SKC: Your previously verified flash/EEPROM hashes match exactly. The PIN
is still calculated from the bytes supplied; it is not substituted from a table.
For the original verified backup the result is 14338, with nine matching records.

CANDIDATE PIN / SKC: A different/changed dump passes this profile's identity,
code/table fingerprints, record checksums, structural checks and consensus.
It has not been independently validated as a new vehicle result. Matching
checksums do not prove the flash and EEPROM belong together or authenticate the
decoded PIN. Independent verification is needed before using a candidate.

Both statuses describe OFFLINE decoding. Neither means the vehicle accepted the
PIN, that a particular tool can perform key adaptation, or that key preparation
is complete. This reader does not produce a full key-programming dataset.

VALIDATION AND CONSERVATIVE LIMITS
- Five firmware regions must match the original verified fingerprints, along
  with the expected ECU/software markers at their known offsets.
- The known reference example is checked internally for each decode. Its PIN
  11352 belongs to that separate test case, never to the selected input by default.
- The reader scans aligned 128-byte EEPROM records of types 08, 09 and 0A.
  It requires all three types and at least three records, checks their header
  checksums, and requires one VIN and identical decoded 22-byte security prefixes.
- Only the validated structure is accepted: decoded bytes 0..3 = 00 00 01 00
  and bytes 17..19 = 00 00 00. Other legitimate security states may be rejected.
- A bad checksum, conflicting historical records or changed code/table regions
  stops decoding. Version 1 does not choose an active record among disagreements.
- It does not validate the whole ECU flash checksum, detect every possible
  mismatched pair, prove a dump's authenticity, or write any corrected data.
- Calibration changes outside checked regions can pass the profile, but change
  the exact hash and therefore receive candidate status.

FILE BEHAVIOUR
Inputs are read-only. The only output is an optional, explicitly selected new
JSON report. No automatic extraction files or modifications to the source are
made. Reports contain the recovered PIN and VIN; keep them with your backups.
No original ECU dump is included in this software ZIP.

FILES
ecu_pin_reader.py - command-line interface, desktop window and input validation
ecu_cipher.py     - translated ECU decoding arithmetic
profile.py        - supported firmware fingerprints and known backup hashes
start_reader.bat  - Windows launcher
test_reader.py    - tests using the separately saved recovery package
VALIDATION.txt    - checks run for this release and remaining testing limits

REPRODUCING THE RELEASE TESTS
Extract your earlier Golf-GTD-PIN-Recovery-Package-2026-10-20.zip separately, then:
  python test_reader.py --source-dir "path to extracted recovery package"
The tests use the original firmware-emulation log, source dump and golden result.
Synthetic modified test data stays in memory or temporary directories.

PROVENANCE
The arithmetic is the translation previously checked against execution of the
original TriCore firmware in Ghidra: 33 mask words for each of two processor IDs.
This application performs the translated arithmetic; it does not run Ghidra or
emulate the firmware on every read. Firmware offsets are profile-specific.

Known-value reference used during the earlier recovery:
https://nefariousmotorsports.com/forum/index.php?topic=23713.0
Record checksum reference used during the earlier recovery:
https://nefariousmotorsports.com/forum/index.php?topic=3574.50;wap2
