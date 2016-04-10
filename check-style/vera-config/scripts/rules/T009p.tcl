#!/usr/bin/tclsh
# Comma should not be preceded by whitespace, but should be followed by one

foreach f [getSourceFileNames] {
    set checkEnabled 1
    foreach t [getTokens $f 1 0 -1 -1 {ccomment comma}] {
        set line [lindex $t 1]
        set column [lindex $t 2]
        set preceding [getTokens $f $line 0 $line $column {}]
        set tokenType [lindex $t 3]
        if {$tokenType == "ccomment"} {
            set comment [lindex $t 0]
            if {[string first "style:comma:start-ignore" $comment] != -1} {
                set checkEnabled 0
            } elseif {[string first "style:comma:end-ignore" $comment] != -1} {
                set checkEnabled 1
            }
            continue
        }
        if {! $checkEnabled} {
            continue;
        }
        if {$preceding == {}} {
            report $f $line "comma should not be preceded by whitespace"
        } else {
            set lastPreceding [lindex [lindex $preceding end] 3]
            if {$lastPreceding == "space"} {
                report $f $line "comma should not be preceded by whitespace"
            }
        }
        set following [getTokens $f $line [expr $column + 1] [expr $line + 1] -1 {}]
        if {$following != {}} {
            set firstFollowing [lindex [lindex $following 0] 3]
            set maybeMacro1 [lindex [lindex $preceding end-2] 0]
            set maybeMacro2 [lindex [lindex $preceding end-4] 0]
            if {$firstFollowing != "space" && $firstFollowing != "newline" &&
                !($lastPreceding == "operator" && $firstFollowing == "leftparen") &&
                !([string first "_CHECK_VERSION" $maybeMacro1] != -1 || [string first "_CHECK_VERSION" $maybeMacro2] != -1)} {
                report $f $line "comma should be followed by whitespace"
            }
        }
    }
}
