# Holloman Signature Detection — Implementation TODO

## Phase 1: Core Integration

- [x] Add `CLI_HASH_HOLLOMAN` to `cli_hash_type` enum in `libclamav/matcher-hash-types.h`
  - Bump `CLI_HASH_AVAIL_TYPES` to include new type
  - Add `"holloman"` to `cli_hash_name()` with 16-byte length in `cli_hash_len()`
- [x] Add `CLI_HASH_HOLLOMAN` cases to hash init/lookup switches in `libclamav/matcher-hash.c`
- [x] Add `holloman_init()` call during engine startup (order 13 default)
- [x] Add `holloman_fingerprint_file()` call in `libclamav/scanners.c` during file scan
  - Compute 16-byte fingerprint from scanned file
  - Call `cli_hm_scan()` with `CLI_HASH_HOLLOMAN`
  - Report virus name on match
- [x] Add `.hlo` database loading in `libclamav/readdb.c`
  - Reuse `cli_loadhash()` with `HASH_PURPOSE_WHOLE_FILE_DETECT`
  - Parse format: `<cluster_id>:<size>:<malware_name>`
  - Support wildcard size (`0` or `*`)
- [x] Link holloman5 library in `CMakeLists.txt`
  - Add `-lholloman5` and include path for `holloman.h`

## Phase 2: Testing

- [x] Unit test: hash type enumeration
  - Verify `cli_hash_name(CLI_HASH_HOLLOMAN)` returns `"holloman"`
  - Verify `cli_hash_len(CLI_HASH_HOLLOMAN)` returns `16`
- [ ] Unit test: signature loading
  - Create test `.hlo` file with 3 known fingerprints
  - Load via `cli_loadhash()`
  - Verify 3 signatures are stored in hash table
  - Test wildcard size (`0`) and exact size matching
- [ ] Unit test: fingerprint computation
  - Fingerprint a known file with both holloman5 CLI and ClamAV
  - Verify identical 16-byte output (bit-exact match)
  - Test with empty file, 1-byte file, 1MB file, 100MB file
- [ ] Unit test: AVX2 availability
  - Verify `holloman_init()` returns 0 on AVX2-capable CPU
  - Verify graceful error (non-zero return) if AVX2 unavailable
  - Verify ClamAV skips holloman matching (no crash) on AVX2-unavailable systems

## Phase 3: Validation

- [x] End-to-end: known-malicious sample detection
  - Take a malware sample with known holloman cluster_id
  - Add its cluster_id to a `.hlo` signature file
  - Scan with ClamAV, verify `FOUND` result with correct virus name
- [x] End-to-end: clean sample passes
  - Take a clean file, verify its fingerprint is NOT in the `.hlo` database
  - Scan with ClamAV, verify `OK` result (no false positive)
- [x] End-to-end: wildcard size matching
  - Signature with size `0` matches files of any size
  - Signature with exact size matches only that size, larger/smaller files do NOT match
- [x] Performance: fingerprint overhead
  - Measure scan time for 1,000 files with and without holloman enabled
  - Verify added time < 2ms per file (holloman5 at ~2.5 GB/s AVX2)
- [x] Performance: hash table lookup
  - Load 100,000 `.hlo` signatures
  - Verify lookup time remains O(1) (hashtab, not linear scan)
- [x] Memory: signature storage
  - Load 500,000 `.hlo` signatures
  - Verify memory usage < 50 MB (16 bytes per signature + overhead)

## Phase 4: Signature Generation Pipeline

- [x] Convert YARA rules to `.hlo` format
  - Script: extract `holloman.cluster_id` from `.yar` files
  - Output: `<cluster_id>:0:<tag>` lines
- [ ] Generate `.hlo` from source2yara.py `--unlabeled-only` output
- [ ] Test hash2yara.py → source2yara.py → .hlo pipeline end-to-end
  - SHA256 hashes → ClickHouse lookup → cluster IDs → YARA rules → .hlo signatures
  - Verify each step preserves the correct fingerprint and tag

## Phase 5: Production Readiness

- [ ] CVD/cdiff support
  - Generate `.hlo.cvd` container using `sigtool`
  - Verify `freshclam` downloads and loads it
- [ ] Logging
  - `cli_dbgmsg()` for each holloman match with cluster_id and virus name
  - `cli_warnmsg()` on holloman_init failure (AVX2 missing)
- [ ] Documentation
  - Add `.hlo` format to ClamAV signature documentation
  - Document hardware requirement (AVX2)
  - Document conversion from YARA rules
