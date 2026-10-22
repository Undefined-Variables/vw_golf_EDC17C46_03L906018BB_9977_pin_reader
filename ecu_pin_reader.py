"""Read-only ECU PIN reader for one explicitly fingerprinted EDC17C46 layout.

Python 3.10+, standard library only. Run without arguments for the desktop UI.
Source dumps are opened read-only; report exports create NEW files only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from ecu_cipher import header_crc, masks
from profile import (KNOWN_EEPROM_SHA256, KNOWN_FLASH_SHA256, PROFILE_NAME,
                     REGION_FINGERPRINTS)

VERSION = "1.0.0"
FLASH_SIZE = 0x200000
EEPROM_SIZE = 0x10000
PAYLOAD_SIZE = FLASH_SIZE + EEPROM_SIZE
HEADER_SIZE = 203
CONTAINER_KEY = bytes.fromhex("FE7FBF5F")
VIN_RE = re.compile(rb"[A-HJ-NPR-Z0-9]{17}")


class DumpError(ValueError):
    """Input cannot be interpreted safely using the supported profile."""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_source(path: Path) -> bytes:
    # Bound reads to supported input sizes, including growing/oversized files.
    with path.open("rb") as f:
        data = f.read(PAYLOAD_SIZE + HEADER_SIZE + 1)
    if len(data) > PAYLOAD_SIZE + HEADER_SIZE:
        raise DumpError("File is larger than any supported dump format.")
    return data


def split_input(data: bytes, flash_data: bytes | None = None):
    """Accept observed XOR container, raw flash+EEPROM, or a raw matching pair."""
    if flash_data is not None:
        if len(data) != EEPROM_SIZE or len(flash_data) != FLASH_SIZE:
            raise DumpError("Separate files must be a 65,536-byte EEPROM and a "
                            "2,097,152-byte flash from the same ECU.")
        return flash_data, data, "separate raw flash and EEPROM"
    if len(data) == PAYLOAD_SIZE + HEADER_SIZE:
        decoded = bytes(v ^ CONTAINER_KEY[i % 4] for i, v in enumerate(data))
        payload = decoded[HEADER_SIZE:]
        return payload[:FLASH_SIZE], payload[FLASH_SIZE:], "203-byte-header XOR container"
    if len(data) == PAYLOAD_SIZE:
        return data[:FLASH_SIZE], data[FLASH_SIZE:], "raw flash followed by EEPROM"
    if len(data) == EEPROM_SIZE:
        raise DumpError("EEPROM alone is insufficient. Supply the matching full flash "
                        "using the second file box or --flash.")
    if len(data) == FLASH_SIZE:
        raise DumpError("This appears to be flash only. Supply the EEPROM as the main "
                        "input and this flash using the second box or --flash.")
    if len(data) == 8192:
        raise DumpError("An 8 KB cluster/24C64 dump is not an engine ECU backup. "
                        "This reader does not decode the NEC instrument cluster.")
    raise DumpError(f"Unsupported file size: {len(data):,} bytes. See README.txt.")


def validate_flash(flash: bytes) -> list[str]:
    if len(flash) != FLASH_SIZE:
        raise DumpError("Incorrect flash size.")
    markers = [(0x11BB0, b"EDC17C46"), (0x4F150, b"03L906018BB"),
               (0x4F171, b"9977")]
    for offset, value in markers:
        if flash[offset:offset + len(value)] != value:
            raise DumpError("Unsupported firmware identity or input format. "
                            "Required profile: " + PROFILE_NAME)
    checked = []
    for name, start, end, expected in REGION_FINGERPRINTS:
        if sha(flash[start:end]) != expected:
            raise DumpError(f"Unsupported or changed firmware: {name} fingerprint "
                            "does not match. No PIN was produced.")
        checked.append(name)
    uid = flash[0x17F00:0x17F10]
    if uid == bytes(16) or uid == b"\xff" * 16:
        raise DumpError("The processor-ID copy is blank; it cannot supply the decoding seed.")
    return checked


def known_value_check(flash: bytes) -> None:
    """Independent published test case; never used as the input's PIN result."""
    uid = bytes.fromhex("410009071400284F74080010110C0400")
    stream = b"".join(w.to_bytes(2, "big") for w in masks(uid, flash))
    encrypted = bytes.fromhex("D9385C35C78E30A8E61434B6DB")
    decoded = bytes(a ^ b for a, b in zip(encrypted, stream[4:17]))
    if decoded != bytes.fromhex("24C5B84732FBEF47006F8F582C"):
        raise DumpError("Decoder self-check failed. No input PIN was produced.")


def decode_images(flash: bytes, eeprom: bytes) -> dict:
    checks = validate_flash(flash)
    if len(eeprom) != EEPROM_SIZE:
        raise DumpError("Incorrect EEPROM size.")
    known_value_check(flash)
    uid = flash[0x17F00:0x17F10]
    stream = b"".join(w.to_bytes(2, "big") for w in masks(uid, flash))
    records = []
    payloads = set()
    vins = set()
    types = set()
    for address in range(0, EEPROM_SIZE, 128):
        r = eeprom[address:address + 128]
        if r[:2] not in (b"\x08\x00", b"\x09\x00", b"\x0a\x00"):
            continue
        # Any apparent security record must validate; never silently ignore a bad copy.
        stored_crc = int.from_bytes(r[2:4], "little")
        if header_crc(r) != stored_crc:
            raise DumpError(f"Record checksum failed at EEPROM 0x{address:04X}. "
                            "Recheck the read; no consensus PIN was produced.")
        vin_bytes = r[32:49]
        if not VIN_RE.fullmatch(vin_bytes):
            raise DumpError(f"Unsupported VIN/record layout at EEPROM 0x{address:04X}.")
        value = bytes(a ^ b for a, b in zip(r[8:30], stream))
        # Conservative invariants observed in the validated security layout.
        # A differing layout/state is rejected, rather than assuming those flags.
        if value[:4] != bytes.fromhex("00000100") or value[17:20] != bytes(3):
            raise DumpError("Decoded record structure does not match the validated layout. "
                            "Possible mismatched flash/EEPROM or unsupported security state.")
        payloads.add(value)
        vins.add(vin_bytes.decode("ascii"))
        types.add(r[0])
        records.append({"offset": f"0x{address:04X}", "type": f"{r[0]:02X}",
                        "header_checksum": f"{stored_crc:04X}", "checksum_passed": True})
    if len(records) < 3 or types != {8, 9, 10}:
        raise DumpError("Need at least three valid matching security records covering "
                        "types 08, 09 and 0A. This dump does not meet that requirement.")
    if len(vins) != 1 or len(payloads) != 1:
        raise DumpError("Security records disagree. An active record cannot be chosen "
                        "reliably by this version; no consensus PIN was produced.")
    value = next(iter(payloads))
    pin = int.from_bytes(value[15:17], "little")
    flash_hash, eeprom_hash = sha(flash), sha(eeprom)
    exact = (flash_hash == KNOWN_FLASH_SHA256 and eeprom_hash == KNOWN_EEPROM_SHA256)
    status = "verified_offline_backup" if exact else "candidate_matching_profile"
    warnings = ["Offline result only. Live vehicle acceptance and key adaptation have not been tested."]
    if not exact:
        warnings.insert(0, "This is a candidate from another/changed dump. Firmware, record "
                        "checksums, structure and consensus match the profile, but this exact "
                        "flash/EEPROM pair has not been independently validated. Checksums "
                        "and repeated copies alone do not authenticate a PIN or prove the pair belongs together.")
    return {
        "tool": "ECU PIN Reader", "version": VERSION, "profile": PROFILE_NAME,
        "status": status, "pin_decimal": pin, "pin_display": f"{pin:05d}",
        "pin_hex": f"0x{pin:04X}",
        "pin_bytes_little_endian": value[15:17].hex(" ").upper(),
        "vin": next(iter(vins)), "processor_id_copy": uid.hex().upper(),
        "flash_sha256": flash_hash, "eeprom_sha256": eeprom_hash,
        "matching_records": len(records), "records": records,
        "firmware_regions_checked": checks, "reference_self_check_passed": True,
        "exact_previously_verified_images": exact, "live_vehicle_tested": False,
        "warnings": warnings,
    }


def decode_file(dump_path: Path, flash_path: Path | None = None) -> dict:
    data = read_source(dump_path)
    flash_data = read_source(flash_path) if flash_path else None
    flash, eeprom, fmt = split_input(data, flash_data)
    result = decode_images(flash, eeprom)
    result["input_format"] = fmt
    result["input_files"] = [{"name": dump_path.name, "bytes": len(data), "sha256": sha(data)}]
    if flash_path:
        result["input_files"].append({"name": flash_path.name,
                                      "bytes": len(flash_data), "sha256": sha(flash_data)})
    result["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    return result


def format_report(result: dict) -> str:
    exact = result["exact_previously_verified_images"]
    label = "PIN / SKC" if exact else "CANDIDATE PIN / SKC"
    lines = [f"{label}: {result['pin_display']}",
             "Status: " + ("Previously verified backup, decoded offline" if exact
                           else "Matching profile; independent validation required"),
             f"VIN: {result['vin']}", f"Profile: {result['profile']}",
             f"Input: {result.get('input_format', 'raw images')}",
             f"PIN bytes: {result['pin_bytes_little_endian']} (little-endian)",
             f"Hex value: {result['pin_hex']}",
             f"Records: {result['matching_records']} agree; all header checksums pass",
             "Firmware: five code/table fingerprints match",
             "Reference decoder self-check: passed", ""]
    lines.extend(result["warnings"])
    lines += ["", "Validated EEPROM records:"]
    lines.extend(f"  {r['offset']}  type {r['type']}  checksum {r['header_checksum']} OK"
                 for r in result["records"])
    lines += ["", "Flash SHA-256: " + result["flash_sha256"],
              "EEPROM SHA-256: " + result["eeprom_sha256"]]
    return "\n".join(lines)


def export_json(result: dict, destination: Path) -> None:
    # Exclusive creation prevents accidental overwrite of a dump or earlier report,
    # including existing symlinks/hard links. No --force option is provided.
    with destination.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
        f.write("\n")


def launch_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
        from tkinter.scrolledtext import ScrolledText
    except ImportError:
        print("The desktop window needs Python's tkinter component. "
              "The command-line reader works without it.", file=sys.stderr)
        return 2

    class ReaderWindow:
        def __init__(self, root):
            self.root = root
            self.result = None
            root.title("ECU PIN Reader 1.0")
            root.geometry("850x720")
            root.minsize(640, 560)
            self.dump = tk.StringVar()
            self.flash = tk.StringVar()
            box = ttk.Frame(root, padding=20)
            box.pack(fill="both", expand=True)
            box.columnconfigure(0, weight=1)
            box.rowconfigure(10, weight=1)
            ttk.Label(box, text="ECU PIN Reader", font=("Segoe UI", 23, "bold")).grid(row=0, column=0, sticky="w")
            ttk.Label(box, text="Offline reader | EDC17C46 | 03L906018BB 9977 layout").grid(row=1, column=0, sticky="w", pady=(2, 14))
            ttk.Label(box, text="Full backup, combined raw dump, or EEPROM file").grid(row=2, column=0, sticky="w")
            self.file_row(box, self.dump, 3)
            ttk.Label(box, text="Matching flash file (only for a separate EEPROM)").grid(row=4, column=0, sticky="w", pady=(10, 0))
            self.file_row(box, self.flash, 5)
            controls = ttk.Frame(box)
            controls.grid(row=6, column=0, sticky="w", pady=16)
            ttk.Button(controls, text="Read PIN", command=self.decode).pack(side="left")
            ttk.Button(controls, text="Clear", command=self.clear).pack(side="left", padx=8)
            self.save = ttk.Button(controls, text="Save JSON report", command=self.save_report, state="disabled")
            self.save.pack(side="left")
            self.pin = tk.Label(box, text="PIN: --", font=("Segoe UI", 28, "bold"), anchor="w")
            self.pin.grid(row=7, column=0, sticky="ew")
            self.status = ttk.Label(box, text="Choose your dump, then select Read PIN.", wraplength=760)
            self.status.grid(row=8, column=0, sticky="w", pady=(4, 12))
            ttk.Label(box, text="Result and validation details").grid(row=9, column=0, sticky="w")
            self.details = ScrolledText(box, height=14, wrap="word", font=("Consolas", 10), state="disabled")
            self.details.grid(row=10, column=0, sticky="nsew", pady=(4, 10))
            ttk.Label(box, text="Reads files only. No vehicle connection or changes to source dumps.").grid(row=11, column=0, sticky="w")
            self.dump.trace_add("write", self.invalidate)
            self.flash.trace_add("write", self.invalidate)

        def file_row(self, parent, variable, row):
            line = ttk.Frame(parent)
            line.grid(row=row, column=0, sticky="ew", pady=(4, 0))
            line.columnconfigure(0, weight=1)
            ttk.Entry(line, textvariable=variable).grid(row=0, column=0, sticky="ew")
            def browse():
                path = filedialog.askopenfilename(title="Choose ECU file", filetypes=[("All files", "*")])
                if path:
                    variable.set(path)
            ttk.Button(line, text="Browse...", command=browse).grid(row=0, column=1, padx=(8, 0))

        def show_details(self, text):
            self.details.configure(state="normal")
            self.details.delete("1.0", "end")
            self.details.insert("1.0", text)
            self.details.configure(state="disabled")

        def invalidate(self, *_):
            self.result = None
            self.save.configure(state="disabled")
            self.pin.configure(text="PIN: --", fg="#222222")
            self.status.configure(text="Choose your dump, then select Read PIN.")
            self.show_details("")

        def clear(self):
            self.dump.set("")
            self.flash.set("")

        def decode(self):
            self.invalidate()
            try:
                if not self.dump.get().strip():
                    raise DumpError("Select a dump first.")
                flash_path = Path(self.flash.get().strip()) if self.flash.get().strip() else None
                result = decode_file(Path(self.dump.get().strip()), flash_path)
            except (OSError, DumpError) as error:
                self.pin.configure(text="No PIN produced", fg="#a51d25")
                self.status.configure(text=str(error))
                self.show_details(str(error))
                return
            self.result = result
            exact = result["exact_previously_verified_images"]
            self.pin.configure(text=("PIN: " if exact else "Candidate PIN: ") + result["pin_display"],
                               fg="#146c43" if exact else "#986000")
            self.status.configure(text=("Previously verified backup. Live vehicle acceptance remains untested."
                                       if exact else "Matching firmware profile. This different dump needs independent validation."))
            self.show_details(format_report(result))
            self.save.configure(state="normal")

        def save_report(self):
            if self.result is None:
                return
            path = filedialog.asksaveasfilename(title="Create a new report", defaultextension=".json",
                                              initialfile="ecu-pin-result.json", filetypes=[("JSON report", "*.json")])
            if path:
                try:
                    export_json(self.result, Path(path))
                except FileExistsError:
                    messagebox.showerror("Choose a new filename", "That file already exists. This tool never overwrites existing files.")
                except OSError as error:
                    messagebox.showerror("Cannot save report", str(error))
                else:
                    messagebox.showinfo("Report saved", path)

    try:
        root = tk.Tk()
    except tk.TclError as error:
        print("Desktop window unavailable: " + str(error) + "\nUse the command-line options; see --help.", file=sys.stderr)
        return 2
    ReaderWindow(root)
    root.mainloop()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline ECU PIN reader; one fingerprinted EDC17C46 profile.")
    parser.add_argument("dump", type=Path, nargs="?", help="full backup, raw combined image, or EEPROM")
    parser.add_argument("--flash", type=Path, help="matching raw flash when dump is a separate EEPROM")
    parser.add_argument("--json", type=Path, dest="report", help="create a new JSON report (never overwrite)")
    parser.add_argument("--gui", action="store_true", help="open the desktop window")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    if args.gui or args.dump is None:
        if args.flash or args.report or (args.gui and args.dump):
            parser.error("Use either the desktop window or command-line file arguments.")
        return launch_gui()
    try:
        result = decode_file(args.dump, args.flash)
        print(format_report(result))
        if args.report:
            export_json(result, args.report)
            print("\nSaved report: " + str(args.report))
        return 0
    except (DumpError, OSError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    if sys.version_info < (3, 10):
        raise SystemExit("Python 3.10 or later is required.")
    raise SystemExit(main())
