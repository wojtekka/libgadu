#!/usr/bin/tclsh
# No C++ style comments ("//")

foreach f [getSourceFileNames] {
    foreach t [getTokens $f 1 0 -1 -1 {cppcomment}] {
        set lineNumber [lindex $t 1]
        report $f $lineNumber "C++ style comment"
    }
}
