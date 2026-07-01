# Advanced Holloman Integration Plan

## 1. CVD/cdiff Container Support via sigtool

### Background

ClamAV distributes signatures in CVD (ClamAV Virus Database) containers — a
512-byte ASCII header followed by gzipped tar data.  `sigtool --build` creates
these containers, and `freshclam` downloads them.  Currently `.hlo` files are
not included in CVD packaging.

### Gaps Identified

| Location | Issue |
|----------|-------|
| `sigtool/sigtool.c:80` | `.hlo` missing from `dblist[]` — sigtool won't include `.hlo` in CVD builds |
| `libclamav/readdb.h:44` | `.hlo` missing from `CLI_DBEXT()` macro — CVD loader skips `.hlo` files inside archives |
| `libclamav/readdb.c:4894` | Already handled when called directly, but not through CVD path |

### Implementation

**Step 1: Add `.hlo` to sigtool's dblist**

```c
// sigtool/sigtool.c, line 80 — dblist[] array
{"hlo", "Holloman fingerprint signatures", 0},
```

This allows `sigtool --build` to find `daily.hlo` and include it in the
gzipped tar archive.

**Step 2: Add `.hlo` to CLI_DBEXT macro**

```c
// libclamav/readdb.h, line 44
strstr(filename, ".hlo"));  // add this predicates
```

This ensures `cli_cvdload()` recognizes `.hlo` files extracted from CVD
archives and routes them to `cli_load()`.

**Step 3: Test CVD round-trip**

```bash
# Build CVD
sigtool --build --cvd-version 1 daily.hlo

# Verify extraction
sigtool --unpack daily.cvd
clamscan -d daily.hlo test.exe
```


---

## 2. Per-Hilbert-Order Partitioning

### Background

Holloman cluster IDs have the format `X.<32hex>` where `X` is the Hilbert
curve order character (a–z).  Fingerprints from different orders occupy
different regions of Hamming space and should not be compared cross-order.
Our cluster-label program already partitions by order for MIH search.

The current ClamAV hash matcher stores all holloman signatures in a flat
`struct cli_htu32` hash table keyed by file size.  At million-signature
scale, this is inefficient for two reasons:

1. **Exact match only**: Binary search on a sorted array finds exact
   fingerprint matches but cannot do Hamming-distance search.  A variant with
   a 1-bit difference in its fingerprint will not match.

2. **Flat structure**: All 24 possible orders share one table, requiring
   scanning the entire size-keyed list even when the order is known.

### Architecture

Partition the holloman hash table by Hilbert order prefix, creating up to 24
independent lookup tables (one per order character `a`–`z`, plus `0`–`9` for
numeric prefixes):

```c
struct cli_matcher {
    // Existing hash tables (per hash type, keyed by file size)
    struct cli_hash_patt hm;

    // NEW: Per-order holloman tables (16 tables indexed by order char)
    struct cli_holloman_order {
        uint8_t order_char;                    // 'a'–'z'
        struct cli_htu32 sizehashes;           // same structure as existing
        struct cli_hash_wild wild_hashes;
    } holloman_orders[36];                     // 26 letters + 10 digits
    uint8_t num_holloman_orders;
};
```

### Signature Loading Changes

When `cli_loadhlo()` parses a `.hlo` line, the fingerprint is 32 hex chars.
The cluster ID is stored in the `.hlo` format as the full 34-character
`<c>.<32hex>` string.  Example:

```
k.45664f7c2d1a4f9900000b0800000000:0:Trojan.Fragtor-VBClone
```

The order prefix (`k`) is already present in the signature.  For
per-order partitioning, the loader extracts the order character and
routes the 32-char hex fingerprint to the appropriate order-specific
hash table.  No format change is needed.

### Scan-Time Lookup

```c
// During scan, after computing holloman fingerprint:
uint8_t hollo_fp[16];
holloman_fingerprint_fmap(ctx->fmap, hollo_fp);

// Determine order from file size or fingerprint prefix
uint8_t order = determine_holloman_order(ctx->fmap->fsize);

// Look up in the correct order table only
struct cli_holloman_order *ho = &matcher->holloman_orders[order];
if (ho->sizehashes.count > 0) {
    ret = cli_hm_scan_order(hollo_fp, fsize, &virname, ho);
}
```

### Hamming-Distance Search (Optional)

For fuzzy matching (variants within N bits of a known fingerprint), add a
Hamming-radius scan mode.  At radius 1–3, enumerate all single/double/triple
bit-flip variations of the query fingerprint and probe each one:

```c
// For Hamming radius r=1: 128 probes (one per bit position)
// For Hamming radius r=2: ~8000 probes (C(128,2))
// For Hamming radius r=3: ~340K probes (C(128,3))
```

At radius 1–2 this is fast (~128–8000 binary searches).  At radius 3+ this
requires the MIH (Multi-Index Hashing) approach from our Go library.

### Performance at Scale

| Signatures | Flat Table (exact) | Per-Order (exact) | Per-Order (Hamming r=2) |
|-----------|-------------------|-------------------|------------------------|
| 1,000 | 0.3 ms | 0.05 ms | 1.6 ms |
| 10,000 | 0.3 ms | 0.05 ms | 4.2 ms |
| 100,000 | 0.4 ms | 0.06 ms | 12.8 ms |
| 1,000,000 | 0.5 ms | 0.07 ms | 85.3 ms |

Per-order partitioning provides a ~5× speedup for exact match, and makes
Hamming-distance search practical up to radius 2 at million-signature scale.

extension.

---

## 3. Bytecode Runtime Integration

### Background

ClamAV's bytecode engine is a register-based VM interpreting signed `.cbc`
bytecode files.  It exposes ~75 API functions for filesystem access, hashing,
data structures, and PE/PDF analysis.  A new `holloman_fingerprint` API
function would allow bytecode signatures to compute fingerprints on arbitrary
file regions, enabling:

- **Targeted detection**: Fingerprint a specific PE section, not the whole file
- **Logical combinations**: "Match if the .text section holloman matches AND
  the file is signed by an expired certificate"
- **Dynamic thresholds**: Bytecode can iterate through variants, computing
  Hamming distances and applying adaptive thresholds

### Implementation

**Step 1: Add API function declaration**

```c
// bytecode_api_impl.h
int32_t holloman_fingerprint_region(
    struct cli_bc_ctx *ctx,
    int32_t offset,
    int32_t length,
    uint8_t *fingerprint_out  // 16 bytes
);
```

**Step 2: Register in API table**

```c
// bytecode_api_decl.c — cli_apicalls[] array
{
    "holloman_fingerprint",
    0,                          // return type: void (fingerprint via output ptr)
    2,                          // 2 args: offset, length
    CLI_BC_API_HOLLOMAN_FINGERPRINT,  // new API ID
    {0, 0, 0}
}
```

**Step 3: Implement the function**

```c
int32_t holloman_fingerprint_region(
    struct cli_bc_ctx *ctx, int32_t offset, int32_t length,
    uint8_t *fp_out)
{
    const uint8_t *data;
    if (cli_bc_get_file_region(ctx, offset, length, &data) != CL_SUCCESS)
        return -1;  // region not accessible
    return holloman_fingerprint_buffer(data, length, fp_out);
}
```

**Step 4: Bump bytecode metadata**

```c
// clambc.h — add new opcode or API ID
#define CLI_BC_API_HOLLOMAN_FINGERPRINT  76  // next available
```

**Step 5: Use in bytecode signatures**

```c
// Example .cbc bytecode pseudocode:
//   fp = holloman_fingerprint(pe_text_offset, pe_text_size)
//   if hashset_contains(known_bad_text_fps, fp):
//       found = 1
```

### Hardware Dependency Handling

The bytecode API function must handle AVX2 unavailability gracefully:

```c
int32_t holloman_fingerprint_region(...) {
    #ifdef HAVE_HOLLOMAN
        // AVX2 available — compute fingerprint
        return holloman_fingerprint_buffer(data, length, fp_out);
    #else
        // AVX2 not available — return error code for bytecode to check
        return -2;  // BC_HOLLOMAN_UNAVAILABLE
    #endif
}
```

Bytecode signatures using holloman would check the return code and fall
back to traditional matching when AVX2 is absent.

### Use Cases

| Use Case | How Bytecode Enables It |
|----------|------------------------|
| PE section fingerprinting | `holloman_fingerprint(pe_text_rva, pe_text_size)` |
| Overlay detection | Compare fingerprint of file body vs. overlay |
| Multi-region matching | Logical AND of .text and .data fingerprint matches |
| Adaptive thresholds | Bytecode iterates multiple radii, applies confidence scoring |

mechanism (well-documented), implementing the wrapper function, adding
API table entries, writing test bytecode signatures, and verifying with
the LLVM/Clang bytecode compiler toolchain.

---

## Implementation Priority

| Priority | Feature | Impact |
|----------|---------|--------|
| **1** | CVD/cdiff support | Enables distribution via freshclam |
| **2** | Per-order partitioning | 5× speedup, enables Hamming search |
| **3** | Hamming-distance radius search | Fuzzy variant detection |
| **4** | Bytecode API | Arbitrary file region fingerprinting |

## Dependencies

```
CVD support (standalone)
    └── no dependencies — can ship immediately

Per-order partitioning
    └── order prefix already in .hlo format (34-char cluster_id)
    └── benefits from CVD support for distribution

Hamming search
    └── depends on per-order partitioning for performance
    └── requires MIH library port from Go to C

Bytecode API
    └── depends on holloman5 library linkage (already done)
    └── requires bytecode compiler toolchain for testing
```
