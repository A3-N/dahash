# dahash Test Fixtures

Run all generated hash and file fixtures:

```bash
./test/run-all.sh
```

The script creates `test/generated/` from the current JSON data, builds a temporary
test binary, and runs `dahash` against every generated hash/file fixture.

Generated fixtures include:

- Hash files from `data/hash-examples/*.json`
- Markerless variants for wrapper formats such as `7-zip`
- A fresh encrypted 7-Zip archive when `7z` and `7z2john.pl` are available

`test/generated/` is disposable and ignored by git.
