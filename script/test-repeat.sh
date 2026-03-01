#!/usr/bin/env bash
# Run test suite multiple times to check for flakey tests
# Usage: ./scripts/test-repeat.sh [runs]

RUNS=${1:-10}
TS=$(date +%Y%m%d-%H%M%S)
LOGDIR=/tmp
FAILURES=()

for i in $(seq 1 $RUNS); do
    LOGFILE=$LOGDIR/bgpgg-test-$TS-$i.log
    echo "=== Run $i/$RUNS === $LOGFILE"
    if ! make test > $LOGFILE 2>&1; then
        grep -E "(FAILED|error\[)" $LOGFILE
        FAILURES+=($i)
    fi
done

echo "=== SUMMARY ==="
if [ ${#FAILURES[@]} -eq 0 ]; then
    echo "All $RUNS runs passed"
else
    echo "Failed runs: ${FAILURES[*]}"
    exit 1
fi
