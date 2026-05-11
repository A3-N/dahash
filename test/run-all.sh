#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
out_dir="${DAHASH_TEST_OUT:-$script_dir/generated}"
hash_dir="$out_dir/hashes"
file_dir="$out_dir/files"
result_dir="$out_dir/results"
manifest="$out_dir/manifest.tsv"
bin="${DAHASH_TEST_BIN:-$out_dir/dahash-test}"
password="${DAHASH_TEST_PASSWORD:-dahash-test-password}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need go
need python3

rm -rf "$out_dir"
mkdir -p "$hash_dir" "$file_dir" "$result_dir"

(
  cd "$repo_root"
  go build -trimpath -o "$bin" ./cmd/dahash
)

python3 - "$repo_root" "$hash_dir" "$manifest" <<'PY'
import json
import pathlib
import sys

repo_root = pathlib.Path(sys.argv[1])
hash_dir = pathlib.Path(sys.argv[2])
manifest = pathlib.Path(sys.argv[3])
examples_dir = repo_root / "data" / "hash-examples"

rows = [("kind", "input", "expected_id", "note")]

for path in sorted(examples_dir.glob("*.json")):
    data = json.loads(path.read_text(encoding="utf-8"))
    hash_type_id = data["hash_type_id"]
    for index, example in enumerate(data.get("examples", []), start=1):
        value = (example.get("value") or "").strip()
        if not value:
            continue

        fixture = hash_dir / f"{hash_type_id}-{index:02d}.hash"
        fixture.write_text(value + "\n", encoding="utf-8")
        rows.append(("hash", str(fixture), hash_type_id, "example hash"))

        if hash_type_id == "7-zip" and value.startswith("$7z$"):
            markerless = hash_dir / f"{hash_type_id}-{index:02d}-markerless.hash"
            markerless.write_text(value[len("$7z$"):] + "\n", encoding="utf-8")
            rows.append(("hash", str(markerless), hash_type_id, "markerless hash body"))

        if hash_type_id == "1password-mobilekeychain-1password-8" and value.startswith("$mobilekeychain$"):
            markerless = hash_dir / f"{hash_type_id}-{index:02d}-markerless.hash"
            markerless.write_text(value[len("$mobilekeychain$"):] + "\n", encoding="utf-8")
            rows.append(("hash", str(markerless), hash_type_id, "markerless hash body"))

        if hash_type_id == "1password-agile-keychain" and value.startswith("$agilekeychain$"):
            markerless = hash_dir / f"{hash_type_id}-{index:02d}-markerless.hash"
            markerless.write_text(value[len("$agilekeychain$"):] + "\n", encoding="utf-8")
            rows.append(("hash", str(markerless), hash_type_id, "markerless hash body"))

        if hash_type_id == "1password-cloud-keychain" and value.startswith("$cloudkeychain$"):
            markerless = hash_dir / f"{hash_type_id}-{index:02d}-markerless.hash"
            markerless.write_text(value[len("$cloudkeychain$"):] + "\n", encoding="utf-8")
            rows.append(("hash", str(markerless), hash_type_id, "markerless hash body"))

manifest.write_text(
    "\n".join("\t".join(row) for row in rows) + "\n",
    encoding="utf-8",
)
PY

seven_zip=""
for candidate in 7z 7za 7zr; do
  if command -v "$candidate" >/dev/null 2>&1; then
    seven_zip="$candidate"
    break
  fi
done

if [[ -n "$seven_zip" ]]; then
  if ! command -v 7z2john.pl >/dev/null 2>&1; then
    echo "missing 7z2john.pl in PATH; encrypted 7-Zip file test cannot run" >&2
    exit 1
  fi

  plaintext="$file_dir/secret.txt"
  archive="$file_dir/generated-7zip.7z"
  printf 'dahash encrypted fixture\n' > "$plaintext"
  "$seven_zip" a -t7z "-p$password" -mhe=on "$archive" "$plaintext" >/dev/null
  printf 'file\t%s\t7-zip\tgenerated encrypted 7z\n' "$archive" >> "$manifest"
else
  echo "warning: no 7z/7za/7zr command found; skipping encrypted 7-Zip file fixture" >&2
fi

if command -v 1password2john.py >/dev/null 2>&1; then
  python3 - "$file_dir" "$manifest" <<'PY'
import base64
import json
import pathlib
import sqlite3
import struct
import sys

file_dir = pathlib.Path(sys.argv[1])
manifest = pathlib.Path(sys.argv[2])

agile_data = b"Salted__" + bytes.fromhex("1122334455667788") + bytes(range(32))
agile_validation = bytes(range(16, 48))
agile = file_dir / "encryptionKeys.js"
agile.write_text(json.dumps({
    "list": [{
        "identifier": "test-key",
        "level": "SL5",
        "data": base64.b64encode(agile_data).decode() + "\n",
        "validation": base64.b64encode(agile_validation).decode() + "\n",
        "iterations": 1000,
    }]
}), encoding="utf-8")

opdata = b"opdata01" + struct.pack("<Q", 16) + bytes.fromhex("00112233445566778899aabbccddeeff") + bytes(range(16)) + bytes(range(32))
profile = file_dir / "profile.js"
profile.write_text("var profile=" + json.dumps({
    "salt": base64.b64encode(bytes.fromhex("c1b981dd8e36340daf420badbfe38ca9")).decode(),
    "masterKey": base64.b64encode(opdata).decode(),
    "iterations": 40000,
}) + ";", encoding="utf-8")

sqlite_path = file_dir / "OnePassword.sqlite"
conn = sqlite3.connect(sqlite_path)
conn.execute("CREATE TABLE profiles (master_key_data BLOB, salt BLOB, iterations INTEGER)")
conn.execute("INSERT INTO profiles VALUES (?, ?, ?)", (opdata, bytes.fromhex("30b952120ca9a190ac673a5e12a358e4"), 50000))
conn.commit()
conn.close()

with manifest.open("a", encoding="utf-8") as fh:
    fh.write(f"file\t{agile}\t1password-agile-keychain\tstandalone 1Password Agile encryptionKeys.js\n")
    fh.write(f"file\t{profile}\t1password-cloud-keychain\tstandalone 1Password OPVault profile.js\n")
    fh.write(f"file\t{sqlite_path}\t1password-cloud-keychain\tstandalone OnePassword.sqlite\n")
PY
else
  echo "warning: no 1password2john.py command found; skipping 1Password file fixtures" >&2
fi

pass_count=0
fail_count=0
skip_count=0
skip_header=1
max_direct_arg_len=100000

while IFS=$'\t' read -r kind input expected_id note; do
  if (( skip_header )); then
    skip_header=0
    continue
  fi
  [[ -z "${kind:-}" ]] && continue

  output="$result_dir/$(basename "$input").out"
  plain_output="$output.plain"
  cmd=("$bin")
  if [[ "$kind" == "hash" ]]; then
    cmd+=("-v")
  fi
  cmd+=("$input")

  if "${cmd[@]}" > "$output" 2>&1; then
    python3 - "$output" "$plain_output" <<'PY'
import pathlib
import re
import sys

raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
plain = re.sub(r"\x1b\[[0-9;]*m", "", raw)
pathlib.Path(sys.argv[2]).write_text(plain, encoding="utf-8")
PY
    if grep -Fq "($expected_id)" "$plain_output"; then
      if [[ "$kind" == "file" ]] && grep -Eq 'john +7z2john|7z2john\.pl|converter' "$plain_output"; then
        echo "FAIL $note: default output leaked converter details"
        echo "     input: $input"
        fail_count=$((fail_count + 1))
      else
        echo "PASS $note: $expected_id"
        pass_count=$((pass_count + 1))
      fi
    else
      echo "FAIL $note: expected ($expected_id)"
      echo "     input: $input"
      echo "     output: $output"
      fail_count=$((fail_count + 1))
    fi
  else
    echo "FAIL $note: command exited non-zero"
    echo "     input: $input"
    echo "     output: $output"
    fail_count=$((fail_count + 1))
  fi

  if [[ "$kind" == "hash" ]]; then
    hash_value="$(<"$input")"
    if (( ${#hash_value} > max_direct_arg_len )); then
      echo "SKIP direct hash arg: $expected_id (hash is too long for reliable argv use; file-content path was tested)"
      skip_count=$((skip_count + 1))
      continue
    fi

    arg_output="$result_dir/$(basename "$input").arg.out"
    arg_plain_output="$arg_output.plain"
    if "$bin" -v "$hash_value" > "$arg_output" 2>&1; then
      python3 - "$arg_output" "$arg_plain_output" <<'PY'
import pathlib
import re
import sys

raw = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
plain = re.sub(r"\x1b\[[0-9;]*m", "", raw)
pathlib.Path(sys.argv[2]).write_text(plain, encoding="utf-8")
PY
      if grep -Fq "($expected_id)" "$arg_plain_output"; then
        echo "PASS direct hash arg: $expected_id"
        pass_count=$((pass_count + 1))
      else
        echo "FAIL direct hash arg: expected ($expected_id)"
        echo "     input fixture: $input"
        echo "     output: $arg_output"
        fail_count=$((fail_count + 1))
      fi
    else
      echo "FAIL direct hash arg: command exited non-zero"
      echo "     input fixture: $input"
      echo "     output: $arg_output"
      fail_count=$((fail_count + 1))
    fi
  fi
done < "$manifest"

echo
echo "fixtures: $out_dir"
echo "passed: $pass_count"
echo "skipped: $skip_count"
echo "failed: $fail_count"

if (( fail_count > 0 )); then
  exit 1
fi
