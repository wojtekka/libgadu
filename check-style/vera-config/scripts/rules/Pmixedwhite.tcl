#!/usr/bin/tclsh
# Don't use mixed tabs and spaces

foreach f [getSourceFileNames] {
    set lineNumber 0
    foreach line [getAllLines $f] {

        incr lineNumber

        if {[string first "\t " $line] != -1 || [string first " \t" $line] != -1} {
            if {[string first "\t *" $line] != -1} {
                # an exception: multiline comments
                continue
            }
            report $f $lineNumber "mixed tabs and spaces"
        }
    }
}
