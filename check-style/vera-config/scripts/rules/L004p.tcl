#!/usr/bin/tclsh
# Line cannot be too long

set maxLength [getParameter "max-line-length" 100]

foreach f [getSourceFileNames] {
    set lineNumber 1
    set checkEnabled 1
    foreach line [getAllLines $f] {
        regsub -all "\t" $line "        " line
        if {[string first "style:maxlinelength:start-ignore" $line] != -1} {
            set checkEnabled 0
        } elseif {[string first "style:maxlinelength:end-ignore" $line] != -1} {
            set checkEnabled 1
        }
        if {([string length $line] > $maxLength) && $checkEnabled} {
            report $f $lineNumber "line is longer than ${maxLength} characters"
        }
        incr lineNumber
    }
}
