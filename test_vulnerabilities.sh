#!/bin/bash
# Test script to demonstrate vulnerability fixes

set -e

ECDSAUTIL=./build/src/cli/ecdsautil
TEST_FILE=/tmp/test_file.txt

# Create a test file
echo "Test content" > $TEST_FILE

# Generate a key pair for testing
echo "Generating test keys..."
SECRET=$($ECDSAUTIL generate-key)
PUBKEY=$(echo "$SECRET" | $ECDSAUTIL show-key)
echo "Secret: $SECRET"
echo "Public key: $PUBKEY"

# Create a valid signature
echo "Creating valid signature..."
SIGNATURE=$(echo "$SECRET" | $ECDSAUTIL sign $TEST_FILE)
echo "Signature: $SIGNATURE"

echo ""
echo "=== Testing Vulnerability Fixes ==="
echo ""

# Test 1: Invalid -n parameter (should fail now)
echo "Test 1: Negative -n value (should fail)"
if $ECDSAUTIL verify -s "$SIGNATURE" -p "$PUBKEY" -n -1 $TEST_FILE 2>&1 | grep -q "Invalid value"; then
    echo "✓ PASS: Negative -n rejected"
else
    echo "✗ FAIL: Negative -n not properly rejected"
fi

echo ""
echo "Test 2: Zero -n value (should fail)"
if $ECDSAUTIL verify -s "$SIGNATURE" -p "$PUBKEY" -n 0 $TEST_FILE 2>&1 | grep -q "Invalid value"; then
    echo "✓ PASS: Zero -n rejected"
else
    echo "✗ FAIL: Zero -n not properly rejected"
fi

echo ""
echo "Test 3: Invalid -n string (should fail)"
if $ECDSAUTIL verify -s "$SIGNATURE" -p "$PUBKEY" -n abc $TEST_FILE 2>&1 | grep -q "Invalid value"; then
    echo "✓ PASS: Invalid -n string rejected"
else
    echo "✗ FAIL: Invalid -n string not properly rejected"
fi

echo ""
echo "Test 4: Valid -n value of 1 (should succeed)"
if $ECDSAUTIL verify -s "$SIGNATURE" -p "$PUBKEY" -n 1 $TEST_FILE; then
    echo "✓ PASS: Valid signature verified with -n 1"
else
    echo "✗ FAIL: Valid signature not verified"
fi

echo ""
echo "Test 5: Valid -n value of 2 (should fail - only 1 signature)"
if ! $ECDSAUTIL verify -s "$SIGNATURE" -p "$PUBKEY" -n 2 $TEST_FILE 2>/dev/null; then
    echo "✓ PASS: Correctly requires 2 signatures when -n 2"
else
    echo "✗ FAIL: Should have failed with insufficient signatures"
fi

echo ""
echo "Test 6: Too many signatures (should fail with limit)"
echo "Creating many unique signatures..."
ARGS=()
for i in {1..1025}; do
    echo "test$i" > /tmp/test_$i.txt
    SIG=$(echo "$SECRET" | $ECDSAUTIL sign /tmp/test_$i.txt)
    ARGS+=("-s" "$SIG")
done
ARGS+=("-p" "$PUBKEY" "$TEST_FILE")
if timeout 10 $ECDSAUTIL verify "${ARGS[@]}" 2>&1 | grep -q "Too many signatures"; then
    echo "✓ PASS: Too many signatures rejected (DoS prevention)"
else
    echo "✗ FAIL: Should reject too many signatures"
fi
rm -f /tmp/test_[0-9]*.txt

echo ""
echo "Test 7: File descriptor handling"
if $ECDSAUTIL verify -s "$SIGNATURE" -p "$PUBKEY" /nonexistent/file 2>&1 | grep -q "open file"; then
    echo "✓ PASS: Proper error handling for missing file"
else
    echo "✗ FAIL: Error handling issue"
fi

echo ""
echo "Test 8: Random number generation (should be fast with urandom)"
START=$(date +%s)
for i in {1..10}; do
    $ECDSAUTIL generate-key > /dev/null
done
END=$(date +%s)
DURATION=$((END - START))
if [ $DURATION -lt 5 ]; then
    echo "✓ PASS: Key generation is fast (${DURATION}s for 10 keys, using urandom)"
else
    echo "⚠ WARNING: Key generation slow (${DURATION}s for 10 keys)"
fi

echo ""
echo "Test 9: Binary search fix - duplicate detection"
# This tests that the set properly detects duplicates (deduplicates them)
# With duplicates, we should have 1 unique sig + 1 unique key = success
if $ECDSAUTIL verify -s "$SIGNATURE" -s "$SIGNATURE" -p "$PUBKEY" -p "$PUBKEY" $TEST_FILE 2>/dev/null; then
    echo "✓ PASS: Duplicate signatures handled correctly (deduplicated)"
else
    echo "✗ FAIL: Duplicate handling issue"
fi

echo ""
echo "Test 10: Binary search - multiple different items"
# Generate another key/signature to test set operations with different items
SECRET2=$($ECDSAUTIL generate-key)
PUBKEY2=$(echo "$SECRET2" | $ECDSAUTIL show-key)
SIGNATURE2=$(echo "$SECRET2" | $ECDSAUTIL sign $TEST_FILE)
# Should succeed with 2 valid signatures and 2 valid keys
if $ECDSAUTIL verify -s "$SIGNATURE" -s "$SIGNATURE2" -p "$PUBKEY" -p "$PUBKEY2" $TEST_FILE 2>/dev/null; then
    echo "✓ PASS: Multiple signatures/keys handled correctly"
else
    echo "✗ FAIL: Multiple item handling issue"
fi

echo ""
echo "=== All vulnerability tests completed ==="

# Cleanup
rm -f $TEST_FILE
