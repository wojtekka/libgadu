#!/usr/bin/tclsh
# Curly brackets should be opened and close at the
# same indentation level (not column)

# example 1:
#	if (something)
#	{
#		contents;
#	}
# should became:
#	if (something) {
#		contents;
#	}

# example 2:
#	if (something.long &&
#		something.else) {
#		contents;
#	}
# should became:
#	if (something.long &&
#		something.else)
#	{
#		contents;
#	}

proc acceptPairs {} {
    global file parens index end

    while {$index != $end} {
        set nextToken [lindex $parens $index]
        set tokenValue [lindex $nextToken 0]

        if {$tokenValue == "\{"} {
            incr index
            set leftParenLine [lindex $nextToken 1]
            if {$leftParenLine > 1} {
                set beforeLeftParenLineContents [getLine $file [expr $leftParenLine - 1]]
            } else {
                set beforeLeftParenLineContents ""
            }
            set leftParenLineContents [getLine $file $leftParenLine]
            regexp {^([[:space:]]*).*$} $leftParenLineContents dummy leftParenIndent

            if {[string index [string trim $leftParenLineContents] 0] == "\{"} {
                if {[getTokens $file [expr $leftParenLine - 1] 0 $leftParenLine -1 {if for while do else}] != ""} {
                    report $file $leftParenLine "opening curly bracket should be in the same line as the conditional expression (unless it's multiline)"
                }
            }

            acceptPairs

            if {$index == $end} {
                report $file $leftParenLine "opening curly bracket is not closed"
                return
            }

            set nextToken [lindex $parens $index]
            incr index
            set tokenValue [lindex $nextToken 0]
            set rightParenLine [lindex $nextToken 1]
            regexp {^([[:space:]]*).*$} [getLine $file $rightParenLine] dummy rightParenIndent

            if {$leftParenIndent != $rightParenIndent} {
                report $file $rightParenLine "closing curly bracket is not at the same indentation level (please take care of multiline expressions)"
            }
        } else {
            return
        }
    }
}

foreach file [getSourceFileNames] {
    set parens [getTokens $file 1 0 -1 -1 {leftbrace rightbrace}]
    set index 0
    set end [llength $parens]
    acceptPairs
    if {$index != $end} {
        report $file [lindex [lindex $parens $index] 1] "excessive closing bracket?"
    }
}
