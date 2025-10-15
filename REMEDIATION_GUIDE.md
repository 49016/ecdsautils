# Security Remediation Guide

## Priority Matrix

| Priority | Vulnerability | Estimated Effort | Risk Level |
|----------|--------------|------------------|------------|
| P0 | Signature Verification Bypass | 2 hours | CRITICAL |
| P0 | Buffer Overflow in parsehex | 4 hours | CRITICAL |
| P1 | Binary Search Logic Error | 1 hour | HIGH |
| P1 | Secret Key Memory Exposure | 3 hours | HIGH |
| P1 | /dev/random DoS | 1 hour | HIGH |
| P2 | File Descriptor Leak | 1 hour | MEDIUM |
| P2 | VLA Stack Overflow | 2 hours | MEDIUM |
| P2 | Race Condition in File Access | 1 hour | MEDIUM |
| P3 | Input Validation Issues | 2 hours | MEDIUM |
| P4 | Signature Malleability | 4 hours | LOW |

**Total Estimated Effort**: 21 hours

---

## Phase 1: Critical Fixes (P0) - Days 1-2

### Fix 1: Signature Verification Bypass

**File**: `src/cli/verify.c`

**Changes Required**:

```diff
--- a/src/cli/verify.c
+++ b/src/cli/verify.c
@@ -26,6 +26,7 @@
 #include "hexutil.h"
 #include "set.h"
 #include "sha256_file.h"
 #include "verify.h"
+#include <errno.h>
+#include <limits.h>
 
 #include <ecdsautil/ecdsa.h>
@@ -79,7 +80,23 @@
         }
         break;
       case 'n':
-        min_good_signatures = atoi(optarg);
+        {
+          char *endptr;
+          errno = 0;
+          long val = strtol(optarg, &endptr, 10);
+          
+          if (errno == ERANGE || val <= 0 || val > LONG_MAX || 
+              endptr == optarg || *endptr != '\0') {
+            fprintf(stderr, "Error: -n requires a positive integer\n");
+            goto out;
+          }
+          
+          if ((unsigned long)val > SIZE_MAX) {
+            fprintf(stderr, "Error: -n value too large\n");
+            goto out;
+          }
+          
+          min_good_signatures = (size_t)val;
+        }
+        break;
     }
   }
 
@@ -88,6 +105,11 @@
     goto out;
   }
 
+  if (min_good_signatures == 0 || min_good_signatures > pubkeys.size) {
+    fprintf(stderr, "Error: -n must be between 1 and number of public keys\n");
+    goto out;
+  }
+
   ecc_int256_t hash;
```

**Testing**:
```bash
# Test valid cases
ecdsautil verify -n 1 -p <key> -s <sig> file
ecdsautil verify -n 2 -p <key1> -p <key2> -s <sig> file

# Test invalid cases (should all fail)
ecdsautil verify -n 0 -p <key> -s <sig> file
ecdsautil verify -n -1 -p <key> -s <sig> file
ecdsautil verify -n abc -p <key> -s <sig> file
ecdsautil verify -n 999999999999999999999 -p <key> -s <sig> file
```

---

### Fix 2: Buffer Overflow in parsehex

**File**: `src/cli/hexutil.c`

**Complete Rewrite**:

```c
int parsehex(void *buffer, const char *string, size_t len) {
  unsigned char *buf = (unsigned char *)buffer;
  const char *str = string;
  
  if (!buffer || !string)
    return 0;
  
  // Get actual length, trimming whitespace
  size_t slen = strlen(string);
  while (slen > 0 && (string[slen-1] == '\n' || 
                      string[slen-1] == '\r' || 
                      string[slen-1] == ' ' || 
                      string[slen-1] == '\t'))
    slen--;
  
  // Must be even number of hex digits
  if ((slen & 1) == 1)
    return 0;
  
  // Must match expected length
  if (slen != 2 * len)
    return 0;
  
  // Parse each byte
  for (size_t i = 0; i < len; i++) {
    unsigned int byte;
    
    // Parse exactly 2 hex digits
    if (sscanf(str + (i * 2), "%2x", &byte) != 1)
      return 0;
    
    // Verify it's a valid byte value
    if (byte > 0xFF)
      return 0;
    
    buf[i] = (unsigned char)byte;
  }
  
  return 1;
}
```

**Testing**:
```bash
# Valid inputs
echo "0123456789abcdef" | ./test_parsehex 8
echo "DEADBEEF" | ./test_parsehex 4

# Invalid inputs (should all fail)
echo "123" | ./test_parsehex 2        # Odd length
echo "12345678" | ./test_parsehex 2   # Wrong length
echo "GGGG" | ./test_parsehex 2       # Invalid hex
echo "" | ./test_parsehex 1           # Empty
```

---

## Phase 2: High Priority Fixes (P1) - Days 3-4

### Fix 3: Binary Search Logic Error

**File**: `src/cli/set.c`

```diff
--- a/src/cli/set.c
+++ b/src/cli/set.c
@@ -140,9 +140,9 @@
     if (cmp == 0)
       return true; /* We're done here: the element already exists */
     else if (cmp < 0)
-      max = cur;
-    else
       min = cur+1;
+    else
+      max = cur;
   }
```

**Testing**:
```c
// Unit test
void test_set_binary_search() {
    set s;
    set_init(&s, sizeof(int), 10);
    
    // Insert elements in order
    int values[] = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19};
    for (int i = 0; i < 10; i++) {
        assert(set_add(&s, &values[i]));
    }
    
    // Verify order
    for (int i = 0; i < 10; i++) {
        int *val = (int*)SET_INDEX(s, i);
        assert(*val == values[i]);
    }
    
    // Test duplicates
    assert(set_add(&s, &values[5]));  // Should return true (already exists)
    assert(s.size == 10);  // Size unchanged
    
    set_destroy(&s);
}
```

---

### Fix 4: Secret Key Memory Exposure

**Files**: `src/cli/sign.c`, `src/cli/keygen.c`

**sign.c**:
```diff
--- a/src/cli/sign.c
+++ b/src/cli/sign.c
@@ -46,12 +46,21 @@
     exit_error(1, 0, "Error while hashing file");
 
   char secret_string[65];
+  memset(secret_string, 0, sizeof(secret_string));
 
-  if (fgets(secret_string, sizeof(secret_string), stdin) == NULL)
+  if (fgets(secret_string, sizeof(secret_string), stdin) == NULL) {
+    explicit_bzero(secret_string, sizeof(secret_string));
     exit_error(1, 0, "Error reading secret");
+  }
 
-  if (!parsehex(secret.p, secret_string, 32))
+  if (!parsehex(secret.p, secret_string, 32)) {
+    explicit_bzero(secret_string, sizeof(secret_string));
+    explicit_bzero(&secret, sizeof(secret));
     exit_error(1, 0, "Error reading secret");
+  }
+
+  // Clear the input buffer immediately
+  explicit_bzero(secret_string, sizeof(secret_string));
 
   ecdsa_sign_legacy(&sig, &hash, &secret);
 
+  // Clear secret after use
+  explicit_bzero(&secret, sizeof(secret));
+
   hexdump(stdout, sig.r.p, 32);
```

**keygen.c**:
```diff
--- a/src/cli/keygen.c
+++ b/src/cli/keygen.c
@@ -59,18 +59,28 @@
 void show_key(void) {
   char secret_string[65];
   ecc_int256_t pubkey, secret;
+  
+  memset(secret_string, 0, sizeof(secret_string));
+  memset(&secret, 0, sizeof(secret));
 
-  if (fgets(secret_string, sizeof(secret_string), stdin) == NULL)
+  if (fgets(secret_string, sizeof(secret_string), stdin) == NULL) {
+    explicit_bzero(secret_string, sizeof(secret_string));
     goto secret_error;
+  }
 
-  if (!parsehex(secret.p, secret_string, 32))
+  if (!parsehex(secret.p, secret_string, 32)) {
+    explicit_bzero(secret_string, sizeof(secret_string));
+    explicit_bzero(&secret, sizeof(secret));
     goto secret_error;
+  }
+
+  explicit_bzero(secret_string, sizeof(secret_string));
 
   public_from_secret(&pubkey, &secret);
 
+  explicit_bzero(&secret, sizeof(secret));
   output_key(&pubkey);
   return;
 
 secret_error:
+  explicit_bzero(&secret, sizeof(secret));
   exit_error(1, 0, "Error reading secret");
 }
```

**Portability Note**: If `explicit_bzero()` is not available:

```c
// Add to a new file: src/cli/secure_memory.h
#pragma once

#include <string.h>

#if defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 25
  // glibc 2.25+ has explicit_bzero
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
  // BSDs have explicit_bzero
#else
  // Fallback implementation
  static inline void explicit_bzero(void *s, size_t n) {
    volatile unsigned char *p = s;
    while (n--)
      *p++ = 0;
  }
#endif
```

---

### Fix 5: /dev/random DoS

**File**: `src/cli/random.c`

```diff
--- a/src/cli/random.c
+++ b/src/cli/random.c
@@ -37,7 +37,7 @@
   int fd;
   size_t read_bytes = 0;
 
-  fd = open("/dev/random", O_RDONLY);
+  fd = open("/dev/urandom", O_RDONLY);
 
   if (fd < 0) {
-    fprintf(stderr, "Can't open /dev/random: %s\n", strerror(errno));
+    fprintf(stderr, "Can't open /dev/urandom: %s\n", strerror(errno));
     goto out_error;
```

**Rationale**: `/dev/urandom` is:
- Cryptographically secure for key generation
- Non-blocking
- Recommended by security experts
- Used by OpenSSL, GnuPG, and other crypto libraries

---

## Phase 3: Medium Priority Fixes (P2) - Days 5-6

### Fix 6: File Descriptor Leak

**Files**: `src/cli/sha256_file.c`, `src/cli/random.c`

```diff
--- a/src/cli/sha256_file.c
+++ b/src/cli/sha256_file.c
@@ -78,7 +78,8 @@
   return 1;
 
 out_error:
-  close(fd);
+  if (fd >= 0)
+    close(fd);
   return 0;
 }
```

Apply same fix to `random.c`.

---

### Fix 7: VLA Stack Overflow

**File**: `src/lib/ecdsa.c`

```diff
--- a/src/lib/ecdsa.c
+++ b/src/lib/ecdsa.c
@@ -170,7 +170,20 @@
 
 size_t ecdsa_verify_list_legacy(const ecdsa_verify_context_t *ctxs, size_t n_ctxs, const ecc_25519_work_t *pubkeys, size_t n_pubkeys) {
   size_t ret = 0, i, j;
+  bool *used;
+  
+  // Sanity check: limit to reasonable number
+  if (n_pubkeys > 10000) {
+    return 0;
+  }
 
-  bool used[n_pubkeys];
+  // Allocate on heap instead of stack
+  used = calloc(n_pubkeys, sizeof(bool));
+  if (!used) {
+    return 0;
+  }
+
-  memset(used, 0, sizeof(used));
 
   for (i = 0; i < n_ctxs; i++) {
@@ -186,6 +199,7 @@
     }
   }
 
+  free(used);
   return ret;
 }
```

---

### Fix 8: Race Condition in File Access

**File**: `src/cli/sha256_file.c`

```diff
--- a/src/cli/sha256_file.c
+++ b/src/cli/sha256_file.c
@@ -40,7 +40,7 @@
   int fd;
 
   if (fname)
-    fd = open(fname, O_RDONLY);
+    fd = open(fname, O_RDONLY | O_NOFOLLOW);
   else
     fd = STDIN_FILENO;
```

---

## Phase 4: Additional Improvements - Days 7+

### Comprehensive Testing Suite

**Create**: `tests/security_tests.c`

```c
#include <assert.h>
#include <stdio.h>
#include "../src/cli/hexutil.h"
#include "../src/cli/set.h"

void test_parsehex_overflow() {
    unsigned char buffer[4];
    
    // Valid input
    assert(parsehex(buffer, "DEADBEEF", 4) == 1);
    assert(buffer[0] == 0xDE && buffer[3] == 0xEF);
    
    // Invalid inputs
    assert(parsehex(buffer, "GGGG", 2) == 0);  // Invalid hex
    assert(parsehex(buffer, "123", 2) == 0);   // Odd length
    assert(parsehex(buffer, "", 0) == 0);      // Empty
    
    printf("[PASS] parsehex overflow tests\n");
}

void test_set_operations() {
    set s;
    set_init(&s, sizeof(int), 5);
    
    int values[] = {5, 3, 7, 1, 9};
    for (int i = 0; i < 5; i++) {
        assert(set_add(&s, &values[i]));
    }
    
    // Check sorted order
    int *items = (int*)s.content;
    assert(items[0] == 1);
    assert(items[1] == 3);
    assert(items[2] == 5);
    assert(items[3] == 7);
    assert(items[4] == 9);
    
    // Test duplicate
    assert(set_add(&s, &values[0]));
    assert(s.size == 5);  // No size increase
    
    set_destroy(&s);
    printf("[PASS] set operations tests\n");
}

int main() {
    test_parsehex_overflow();
    test_set_operations();
    
    printf("\n[SUCCESS] All security tests passed\n");
    return 0;
}
```

### Build Configuration

**Update**: `CMakeLists.txt`

```cmake
# Add security flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -pie")

# Enable sanitizers for debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address,undefined")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
endif()
```

---

## Verification and Testing

### Manual Testing Checklist

- [ ] Test signature verification with valid signatures
- [ ] Test signature verification with invalid signatures
- [ ] Test with -n parameter (valid and invalid values)
- [ ] Test parsehex with various inputs
- [ ] Test key generation multiple times
- [ ] Test signing and verification end-to-end
- [ ] Test with large numbers of signatures/keys
- [ ] Test error paths and cleanup

### Automated Testing

```bash
# Run with sanitizers
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
./tests/security_tests

# Run with valgrind
valgrind --leak-check=full --show-leak-kinds=all ./ecdsautil generate-key

# Fuzz test (requires AFL)
afl-fuzz -i testcases -o findings ./ecdsautil verify -s @@ -p <key> file
```

### Static Analysis

```bash
# Cppcheck
cppcheck --enable=all --inconclusive --std=c99 src/

# Clang-tidy
clang-tidy src/cli/*.c -- -I include

# Flawfinder
flawfinder --minlevel=2 src/
```

---

## Deployment Strategy

### Version 0.4.3 (Security Release)

**Release Notes**:
```
SECURITY UPDATE - All users should upgrade immediately

Critical Fixes:
- Fixed signature verification bypass (CVE-XXXX-XXXXX)
- Fixed buffer overflow in hex parsing (CVE-XXXX-XXXXX)

High Priority Fixes:
- Fixed binary search logic error
- Implemented secure memory clearing for secrets
- Switched to /dev/urandom for better availability

Medium Priority Fixes:
- Fixed file descriptor leaks
- Added bounds checking for arrays
- Fixed TOCTOU race condition

Breaking Changes:
- None

Upgrade Path:
- Direct replacement of binaries
- No configuration changes needed
```

### Rollout Plan

1. **Day 0**: Internal testing
2. **Day 1-3**: Beta testing with select users
3. **Day 4**: Public announcement of security issues
4. **Day 5**: Release v0.4.3
5. **Day 6+**: Monitor for issues

---

## Long-Term Security Improvements

### Code Audit
- Professional security audit
- Penetration testing
- Formal verification of crypto operations

### Process Improvements
- Security-focused code reviews
- Automated security testing in CI/CD
- Regular dependency updates
- Bug bounty program

### Documentation
- Security best practices guide
- Threat model documentation
- Secure deployment guidelines
- Incident response plan

---

## Contact Information

**Security Issues**: Report to security@example.com (PGP key: XXXX)

**Coordination**: 90-day coordinated disclosure policy

**Acknowledgments**: Security researchers will be credited in release notes
