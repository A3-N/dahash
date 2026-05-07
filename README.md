# dahash

`dahash` is a Go hash identification tool in progress.

The first implemented layer is the core schema in `pkg/schema`. It defines the
canonical data model for hash types, matchers, observed characteristics, sample
hashes, source attribution, and Hashcat/John/extractor references.

Hash type knowledge is stored dynamically as JSON under `data/hash-types`. The
Go matcher engine is expected to load these definitions rather than hardcode
hash formats.

## Usage

```powershell
go run .\cmd\dahash --help
go run .\cmd\dahash identify
go run .\cmd\dahash identify <hash>
go run .\cmd\dahash <hash>
go run .\cmd\dahash -i <hash>
go run .\cmd\dahash -f <file>
go run .\cmd\dahash -e -h -j <hash>
```

Flags:

- `-e`, `--examples`: print the matcher reason and example hashes for each match.
- `-f`, `--file`: convert an explicit supported file type with a John helper from `PATH`, then identify the extracted hash.
- `-h`, `--hashcat`: print a Hashcat crack command template for matching modes.
- `-i <hash>`: identify the supplied hash without using the `identify` command.
- `-j`, `--john`: print a John the Ripper crack command template for matching formats.
- `--data <dir>`: load `sources.json` and `hash-types/` from a different data directory.

When `identify` is run without a hash argument, dahash prompts for one.

File conversion is intentionally explicit. Generic extensions like `.txt` are
not guessed. Supported file conversion rules live in `data/file-converters.json`;
for example `.p12` and `.pfx` use `pfx2john.py` when that helper is present in
`PATH`. If a required helper is missing, dahash points to:
`https://github.com/openwall/john/tree/bleeding-jumbo/run`.

Example:

```text
go run .\cmd\dahash identify -e -h -j 'EXAMPLE\user:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::'

Likely
[1] NTLM (ntlm) score=175 confidence=strong
    Hashcat: 1000
    John: nt
    Reason: regex matcher ntlm.haiti.022 matched ^(.+\\)?\w+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::$
    Example hash: b4b9b02e6f09a9bd760f388b67351e2b
    Hashcat command: hashcat -m 1000 'EXAMPLE\user:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::' <wordlist>
    John command: printf '%s\n' 'EXAMPLE\user:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::' > dahash.hash && john --format=nt dahash.hash --wordlist=<wordlist>
```
