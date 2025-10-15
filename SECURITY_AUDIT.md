# Security Audit Report

## Critical Vulnerabilities Found

### 1. Integer Overflow/Underflow in verify.c (Line 82)
**Severity: CRITICAL**

```c
case 'n':
  min_good_signatures = atoi(optarg);
```

**Issue**: No validation of the `-n` parameter. User can provide:
- Negative values (e.g., `-n -1`)
- Zero value (`-n 0`) 
- Extremely large values causing integer overflow

**Impact**: 
- With `-n 0`, any signature would be considered valid (0 >= 0)
- Allows bypassing signature verification completely
- Can trick systems into accepting unauthorized files

**Exploit**:
```bash
# Bypass all signature verification
ecdsautil verify -s fake_sig -p fake_key -n 0 file
# Returns success (0) even with invalid signatures
```

### 2. Binary Search Logic Error in set.c (Line 143)
**Severity: HIGH**

```c
if (cmp == 0)
  return true;
else if (cmp < 0)  // BUG: Should be cmp > 0
  max = cur;
else
  min = cur+1;
```

**Issue**: The comparison logic is inverted. When `memcmp` returns negative (element at cur is less than el), we should move `min` forward, not `max` backward.

**Impact**:
- Binary search may fail to find existing elements
- May insert duplicates
- Can cause incorrect signature verification results
- Breaks the sorted invariant of the set

### 3. File Descriptor Leak in sha256_file.c (Line 81)
**Severity: MEDIUM**

```c
out_error:
  close(fd);  // fd might be -1
  return 0;
```

**Issue**: When `open()` fails (line 47), `fd` is -1, but we still call `close(fd)` in error handler.

**Impact**:
- Undefined behavior when closing an invalid fd
- POSIX says close(-1) returns EBADF, but still calls it unnecessarily
- Resource handling issue

### 4. Stack Overflow via Variable Length Array in verify.c (Line 99)
**Severity: CRITICAL**

```c
ecdsa_verify_context_t ctxs[signatures.size];
```

**Issue**: Uses VLA (Variable Length Array) on stack with user-controlled size.

**Impact**:
- Attacker can provide unlimited `-s` parameters
- Each signature context is ~100+ bytes
- Can cause stack overflow and crash or code execution
- No bounds checking on array size

**Exploit**:
```bash
# Provide thousands of signatures to overflow stack
ecdsautil verify $(python -c "print(' -s ' + 'a'*128)*10000") -p key file
```

### 5. Blocking Random Source in random.c (Line 40)
**Severity: MEDIUM**

```c
fd = open("/dev/random", O_RDONLY);
```

**Issue**: Uses `/dev/random` instead of `/dev/urandom`.

**Impact**:
- `/dev/random` blocks when entropy pool is depleted
- Can cause DoS by making key generation hang indefinitely
- Modern guidance recommends `/dev/urandom` for cryptographic operations
- Especially problematic in headless/VM environments

### 6. Off-by-One Error in verify.c (Line 86)
**Severity: MEDIUM**

```c
if (optind > argc || pubkeys.size == 0 || signatures.size == 0) {
```

**Issue**: Should be `optind >= argc` when expecting a filename, or the check doesn't properly validate if argv[optind] exists.

**Impact**:
- May access argv out of bounds if optind == argc
- Line 93 uses `(optind <= argc) ? argv[optind] : NULL`
- Inconsistent boundary checking

### 7. Format String in hexutil.c (Minor)
**Severity: LOW**

```c
ret = sscanf(string, "%02hhx", (char*)(buffer++));
```

**Issue**: While not exploitable here, using sscanf with user input requires careful validation. The length check prevents overflow, but relies on strlen which could be manipulated if string isn't null-terminated.

**Impact**: 
- Currently mitigated by length checks
- Defense in depth would use explicit bounds

## Vulnerability Summary

| ID | Severity | File | Line | Issue |
|----|----------|------|------|-------|
| 1 | CRITICAL | verify.c | 82 | No validation on -n parameter, allows bypass |
| 2 | HIGH | set.c | 143 | Binary search logic inverted |
| 3 | MEDIUM | sha256_file.c | 81 | Close on invalid fd |
| 4 | CRITICAL | verify.c | 99 | Stack overflow via VLA |
| 5 | MEDIUM | random.c | 40 | Blocking random source |
| 6 | MEDIUM | verify.c | 86 | Off-by-one boundary check |
| 7 | LOW | hexutil.c | 42 | Format string (mitigated) |

## Recommended Fixes

All vulnerabilities will be fixed in this PR.
