"""Regression checks using the earlier recovery package as private test data.

Run: python test_reader.py --source-dir PATH_TO_EXTRACTED_RECOVERY_PACKAGE
No ECU dump or private VIN is embedded in this test file.
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import ecu_pin_reader as reader
from ecu_cipher import header_crc, masks

SOURCE = None


class ReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (SOURCE / "source-ecu-full-backup.bin").read_bytes()
        cls.flash = (SOURCE / "R500-GTD-flash.bin").read_bytes()
        cls.eeprom = (SOURCE / "R500-GTD-eeprom.bin").read_bytes()
        cls.golden = json.loads((SOURCE / "recovered-immo-data.json").read_text())
        cls.addresses = [int(r["eeprom_record_offset"], 16) for r in cls.golden["records"]]

    @staticmethod
    def repair_record(data, address):
        crc = header_crc(data[address:address + 128])
        data[address + 2:address + 4] = crc.to_bytes(2, "little")

    def test_original_container_exact_result(self):
        f, e, _ = reader.split_input(self.raw)
        self.assertEqual(f, self.flash)
        self.assertEqual(e, self.eeprom)
        result = reader.decode_images(f, e)
        self.assertEqual(result["pin_decimal"], self.golden["pin_skc_decimal"])
        self.assertEqual(result["vin"], self.golden["vehicle_vin"])
        self.assertEqual(result["matching_records"], 9)
        self.assertTrue(result["exact_previously_verified_images"])

    def test_raw_combined_and_pair(self):
        for data, extra in [(self.flash + self.eeprom, None), (self.eeprom, self.flash)]:
            f, e, _ = reader.split_input(data, extra)
            self.assertEqual(reader.decode_images(f, e)["pin_decimal"], self.golden["pin_skc_decimal"])

    def test_matches_original_firmware_emulation_all_66_words(self):
        text = (SOURCE / "firmware-emulation.txt").read_text()
        cases = text.split("UID ")[1:]
        self.assertEqual(len(cases), 2)
        for case in cases:
            uid = bytes.fromhex(case.split()[0])
            observed = [int(w, 16) for w in re.findall(r"^\d{2} ([a-f0-9]{4}) steps=", case, re.M)]
            self.assertEqual(len(observed), 33)
            self.assertEqual(masks(uid, self.flash), observed)

    def test_changed_pin_is_computed_and_flagged_candidate(self):
        eeprom = bytearray(self.eeprom)
        # Fixed mask from the independent firmware-emulation result in the report.
        new_pin = 24680
        encrypted = bytes(a ^ b for a, b in zip(new_pin.to_bytes(2, "little"), bytes.fromhex("9D7E")))
        for a in self.addresses:
            eeprom[a + 23:a + 25] = encrypted
            self.repair_record(eeprom, a)
        result = reader.decode_images(self.flash, bytes(eeprom))
        self.assertEqual(result["pin_decimal"], new_pin)
        self.assertEqual(result["status"], "candidate_matching_profile")
        self.assertFalse(result["exact_previously_verified_images"])

    def test_other_uid_and_known_reference_fields(self):
        # Full synthetic records use the separate CPU's original emulation log,
        # not this reader's mask generator, to produce the test ciphertext.
        chunks = (SOURCE / "firmware-emulation.txt").read_text().split("UID ")[1:]
        reference = chunks[1]
        uid = bytes.fromhex(reference.split()[0])
        words = [int(w, 16) for w in re.findall(r"^\d{2} ([a-f0-9]{4}) steps=", reference, re.M)]
        stream = b"".join(w.to_bytes(2, "big") for w in words)
        flash = bytearray(self.flash)
        flash[0x17F00:0x17F10] = uid
        eeprom = bytearray(self.eeprom)
        plain = bytes.fromhex("00000100" + "24C5B84732FBEF47006F8F582C" + "0000001BD4")
        ciphertext = bytes(a ^ b for a, b in zip(plain, stream))
        for a in self.addresses:
            eeprom[a + 8:a + 30] = ciphertext
            eeprom[a + 32:a + 49] = b"WVWZZZ1KZBW000001"
            self.repair_record(eeprom, a)
        result = reader.decode_images(bytes(flash), bytes(eeprom))
        self.assertEqual(result["pin_decimal"], 11352)
        self.assertEqual(result["vin"], "WVWZZZ1KZBW000001")
        self.assertEqual(result["status"], "candidate_matching_profile")

    def test_bad_checksum_rejected(self):
        eeprom = bytearray(self.eeprom)
        eeprom[0x97] ^= 1
        with self.assertRaisesRegex(reader.DumpError, "checksum failed"):
            reader.decode_images(self.flash, bytes(eeprom))

    def test_conflicting_valid_records_rejected(self):
        eeprom = bytearray(self.eeprom)
        eeprom[0x97] ^= 1
        self.repair_record(eeprom, 0x80)
        with self.assertRaisesRegex(reader.DumpError, "disagree"):
            reader.decode_images(self.flash, bytes(eeprom))

    def test_different_vin_in_valid_record_rejected(self):
        eeprom = bytearray(self.eeprom)
        eeprom[0xA0:0xB1] = b"WVWZZZ1KZBW000001"
        self.repair_record(eeprom, 0x80)
        with self.assertRaisesRegex(reader.DumpError, "disagree"):
            reader.decode_images(self.flash, bytes(eeprom))

    def test_wrong_flash_uid_rejected(self):
        flash = bytearray(self.flash)
        flash[0x17F00] ^= 1
        with self.assertRaisesRegex(reader.DumpError, "structure"):
            reader.decode_images(bytes(flash), self.eeprom)

    def test_changed_code_or_tables_rejected(self):
        for name, start, _, _ in reader.REGION_FINGERPRINTS:
            with self.subTest(region=name):
                flash = bytearray(self.flash)
                flash[start] ^= 1
                with self.assertRaisesRegex(reader.DumpError, "fingerprint"):
                    reader.decode_images(bytes(flash), self.eeprom)

    def test_incomplete_and_wrong_inputs_rejected(self):
        for data in [b"", self.raw[:-1], self.eeprom, self.flash, bytes(8192), bytes(len(self.raw))]:
            with self.subTest(size=len(data)):
                with self.assertRaises(reader.DumpError):
                    f, e, _ = reader.split_input(data)
                    reader.decode_images(f, e)

    def test_missing_record_types_rejected(self):
        eeprom = bytearray(self.eeprom)
        for a in self.addresses:
            if eeprom[a] == 10:
                eeprom[a:a + 128] = b"\xff" * 128
        with self.assertRaisesRegex(reader.DumpError, "types 08, 09 and 0A"):
            reader.decode_images(self.flash, bytes(eeprom))

    def test_non_profile_flash_change_is_candidate(self):
        flash = bytearray(self.flash)
        flash[0x180000] ^= 1
        result = reader.decode_images(bytes(flash), self.eeprom)
        self.assertEqual(result["pin_decimal"], self.golden["pin_skc_decimal"])
        self.assertEqual(result["status"], "candidate_matching_profile")

    def test_cli_export_and_source_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "backup with spaces.bin"
            source.write_bytes(self.raw)
            report = Path(tmp) / "result.json"
            command = [sys.executable, str(Path(reader.__file__)), str(source), "--json", str(report)]
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(report.read_text())["pin_decimal"], self.golden["pin_skc_decimal"])
            self.assertEqual(source.read_bytes(), self.raw)
            before = report.read_bytes()
            second = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(second.returncode, 2)
            self.assertEqual(report.read_bytes(), before)
            with self.assertRaises(FileExistsError):
                reader.export_json({"dummy": True}, source)
            self.assertEqual(source.read_bytes(), self.raw)

    def test_optimized_python_rejects_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            eeprom = bytearray(self.eeprom)
            eeprom[0x97] ^= 1
            path = Path(tmp) / "bad.bin"
            path.write_bytes(self.flash + eeprom)
            run = subprocess.run([sys.executable, "-O", reader.__file__, str(path)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 2)
            self.assertNotIn("PIN / SKC:", run.stdout)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    args = parser.parse_args()
    SOURCE = args.source_dir
    unittest.main(argv=[sys.argv[0]], verbosity=2)
