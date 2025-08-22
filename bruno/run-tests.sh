#!/bin/bash

echo " Starting Comprehensive Bruno Test Suite"
echo "=========================================="
echo ""
echo "Running all test phases in sequence with proper token chaining..."
echo ""

cd bruno

# Run comprehensive test suite in single command to maintain token state
echo "Running comprehensive workflow: Authentication → MSP Lifecycle → Client Operations"
bru run --env docker 1-authentication 3-msp-lifecycle 4-client-operations

echo ""
echo " Comprehensive Test Suite Complete!"
echo "======================================"