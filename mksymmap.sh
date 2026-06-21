#!/bin/sh
BINARY="$1"
MAP="${BINARY}.symmap"

nm -n "$BINARY" 2>/dev/null | awk '/^[0-9a-f]+ [tTdDwWbB]/ {print "sym", $3, "0x" $1}' > "$MAP"

objdump -d -l "$BINARY" 2>/dev/null | awk '
BEGIN { file = ""; line = ""; emitted = 0 }
/^[^[:space:]]/ && /:[0-9]+$/ {
    split($0, a, ":")
    file = a[1]
    line = a[2] + 0
    emitted = 0
    next
}
/^\s+[0-9a-f]+:/ {
    if (file != "" && !emitted) {
        split($1, a, ":")
        n = split(file, parts, "/")
        print "line", parts[n] ":" line, "0x" a[1]
        emitted = 1
    }
}' >> "$MAP"
