# Security Fixes Summary

This document provides a detailed before/after comparison of all security fixes.

---

## Fix 1: Integer Overflow in verify.c

**Location**: `src/cli/verify.c` line 82

### Before (Vulnerable)
```c
case 'n':
    min_good_signatures = atoi(optarg);
```

**Problems**:
- No validation on input
- `atoi()` returns 0 on error or for "0"
- Negative values could wrap around
- Can set `min_good_signatures = 0` to bypass all checks

### After (Fixed)
```c
case 'n':
    {
        char *endptr;
        errno = 0;
        long val = strtol(optarg, &endptr, 10);
        if (errno != 0 || *endptr != '\0' || val < 1 || val > LONG_MAX) {
            fprintf(stderr, "Invalid value for -n: %s (must be a positive integer)\n", optarg);
            goto out;
        }
        min_good_signatures = (size_t)val;
    }
```

**Improvements**:
- Uses `strtol()` for proper error detection
- Validates input is a positive integer (>= 1)
- Checks for conversion errors
- Ensures entire string was consumed
- Prevents bypass attacks

---

## Fix 2: Stack Overflow in verify.c

**Location**: `src/cli/verify.c` lines 99-111

### Before (Vulnerable)
```c
if (optind > argc || pubkeys.size == 0 || signatures.size == 0) {
    fprintf(stderr, "Usage: ...\n");
    goto out;
}

ecc_int256_t hash;
if (!sha256_file((optind <= argc) ? argv[optind] : NULL, hash.p)) {
    fprintf(stderr, "Error while hashing file\n");
    goto out;
}

{
    ecdsa_verify_context_t ctxs[signatures.size];  // VLA on stack!
    for (size_t i = 0; i < signatures.size; i++)
        ecdsa_verify_prepare_legacy(&ctxs[i], &hash, SET_INDEX(signatures, i));
    
    size_t good_signatures = ecdsa_verify_list_legacy(ctxs, signatures.size, pubkeys.content, pubkeys.size);
    
    if (good_signatures >= min_good_signatures)
        ret = 0;
}
```

**Problems**:
- Variable-length array (VLA) on stack with user-controlled size
- No limit on number of signatures
- Could allocate megabytes on stack
- Stack overflow leads to crash or RCE

### After (Fixed)
```c
if (optind >= argc || pubkeys.size == 0 || signatures.size == 0) {  // Fixed: >= not >
    fprintf(stderr, "Usage: ...\n");
    goto out;
}

if (signatures.size > 1024) {  // NEW: Limit on signatures
    fprintf(stderr, "Too many signatures (max 1024)\n");
    goto out;
}

ecc_int256_t hash;
if (!sha256_file(argv[optind], hash.p)) {  // Fixed: Direct access, not ternary
    fprintf(stderr, "Error while hashing file\n");
    goto out;
}

{
    ecdsa_verify_context_t *ctxs = malloc(sizeof(ecdsa_verify_context_t) * signatures.size);  // Heap allocation
    if (!ctxs) {
        fprintf(stderr, "Memory allocation failed\n");
        goto out;
    }
    
    for (size_t i = 0; i < signatures.size; i++)
        ecdsa_verify_prepare_legacy(&ctxs[i], &hash, SET_INDEX(signatures, i));
    
    size_t good_signatures = ecdsa_verify_list_legacy(ctxs, signatures.size, pubkeys.content, pubkeys.size);
    
    if (good_signatures >= min_good_signatures)
        ret = 0;
    
    free(ctxs);  // NEW: Cleanup
}
```

**Improvements**:
- Replaced VLA with `malloc()` (heap allocation)
- Added 1024 signature limit to prevent DoS
- Added memory allocation error checking
- Proper cleanup with `free()`
- Fixed boundary check (optind >= argc)
- Removed unsafe ternary operator

---

## Fix 3: Binary Search Logic Error in set.c

**Location**: `src/cli/set.c` line 143

### Before (Vulnerable)
```c
while (max > min) {
    size_t cur = min + (max - min)/2;
    int cmp = memcmp(set_index(set, cur), el, set->el_size);
    
    if (cmp == 0)
        return true;
    else if (cmp < 0)  // BUG: Logic inverted!
        max = cur;
    else
        min = cur+1;
}
```

**Problem**:
- When `cmp < 0`, element at cur is LESS than el
- Should move `min` forward, not `max` backward
- Causes binary search to fail
- Can insert duplicates and break sorting

### After (Fixed)
```c
while (max > min) {
    size_t cur = min + (max - min)/2;
    int cmp = memcmp(set_index(set, cur), el, set->el_size);
    
    if (cmp == 0)
        return true;
    else if (cmp > 0)  // FIXED: Correct comparison
        max = cur;
    else
        min = cur+1;
}
```

**Improvement**:
- Correct binary search logic
- When element at cur > el, move max down
- When element at cur < el, move min up
- Maintains sorted invariant
- Prevents duplicates

---

## Fix 4: File Descriptor Leak in sha256_file.c

**Location**: `src/cli/sha256_file.c` lines 77-83

### Before (Vulnerable)
```c
ecdsa_sha256_final(&ctx, hash);

close(fd);
return 1;

out_error:
    close(fd);  // fd might be -1!
    return 0;
```

**Problem**:
- When `open()` fails, fd = -1
- Still calls `close(-1)` in error path
- Undefined behavior
- Poor resource management

### After (Fixed)
```c
ecdsa_sha256_final(&ctx, hash);

if (fname)  // NEW: Only close if we opened it
    close(fd);
return 1;

out_error:
    if (fname && fd >= 0)  // NEW: Check validity
        close(fd);
    return 0;
```

**Improvements**:
- Only close if file was actually opened
- Check fd >= 0 before closing
- Don't close STDIN_FILENO in success path if fname is NULL
- Proper resource management

---

## Fix 5: Blocking Random Source in random.c

**Location**: `src/cli/random.c` line 40

### Before (Vulnerable)
```c
fd = open("/dev/random", O_RDONLY);

if (fd < 0) {
    fprintf(stderr, "Can't open /dev/random: %s\n", strerror(errno));
    goto out_error;
}
```

**Problems**:
- `/dev/random` blocks when entropy pool depleted
- Can hang indefinitely
- Problematic in VMs, containers, headless servers
- Not recommended by modern crypto standards

### After (Fixed)
```c
fd = open("/dev/urandom", O_RDONLY);

if (fd < 0) {
    fprintf(stderr, "Can't open /dev/urandom: %s\n", strerror(errno));
    goto out_error;
}
```

**Improvements**:
- Uses `/dev/urandom` which never blocks
- Recommended by cryptographers since 2014
- Suitable for cryptographic operations
- Works reliably in all environments
- No denial of service risk

---

## Fix 6: Signature Limit Check

**Location**: `src/cli/verify.c` line 56-61

### Added (New)
```c
case 's':
    if (signatures.size >= 1024) {  // NEW: Pre-check
        fprintf(stderr, "Too many signatures (max 1024)\n");
        goto out;
    }
    
    if (!parsehex(signature, optarg, sizeof(signature))) {
        fprintf(stderr, "Error while reading signature %s\n", optarg);
        break;
    }
    // ... rest of code
```

**Improvement**:
- Checks signature count BEFORE processing
- Prevents resource exhaustion early
- Complements the post-parse check
- Provides clear error message

---

## Testing

All fixes verified with comprehensive test suite in `test_vulnerabilities.sh`:

```bash
$ ./test_vulnerabilities.sh

=== Testing Vulnerability Fixes ===

Test 1: Negative -n value (should fail)
✓ PASS: Negative -n rejected

Test 2: Zero -n value (should fail)
✓ PASS: Zero -n rejected

Test 3: Invalid -n string (should fail)
✓ PASS: Invalid -n string rejected

Test 4: Valid -n value of 1 (should succeed)
✓ PASS: Valid signature verified with -n 1

Test 5: Valid -n value of 2 (should fail - only 1 signature)
✓ PASS: Correctly requires 2 signatures when -n 2

Test 6: Too many signatures (should fail with limit)
✓ PASS: Too many signatures rejected (DoS prevention)

Test 7: File descriptor handling
✓ PASS: Proper error handling for missing file

Test 8: Random number generation (should be fast with urandom)
✓ PASS: Key generation is fast (using urandom)

Test 9: Binary search fix - duplicate detection
✓ PASS: Duplicate signatures handled correctly

Test 10: Binary search - multiple different items
✓ PASS: Multiple signatures/keys handled correctly
```

---

## Summary

| Fix | Type | Severity | Lines Changed |
|-----|------|----------|---------------|
| Integer validation | Input validation | CRITICAL | 10 |
| Stack overflow | Memory safety | CRITICAL | 20 |
| Binary search | Logic error | HIGH | 1 |
| FD leak | Resource management | MEDIUM | 4 |
| Random source | Availability | MEDIUM | 2 |
| Boundary check | Memory safety | MEDIUM | 1 |

**Total**: 38 lines changed across 4 files to fix 6+ vulnerabilities.
