# Regular Expression Cheat-sheet

## Anchors

    ^   Matches at the start of string or start of line if multi-line mode is enabled. Many regex implementations have multi-line mode enabled by default.

    $   Matches at the end of string or end of line if multi-line mode is enabled. Many regex implementations have multi-line mode enabled by default.
    \\A  Matches at the start of the search string.
    \\Z  Matches at the end of the search string, or before a newline at the end of the string.
    \\z  Matches at the end of the search string.
    \\b  Matches at word boundaries.
    \\B  Matches anywhere but word boundaries.

## Character Classes

Character classes can be used in ranges.

    .         Matches any character except newline (matches newline in single-line)
    \\s        Matches white space characters.
    \\S        Matches anything but white space characters.
    \\d        Matches digits. Equivalent to \[0-9\].
    \\D        Matches anything but digits. Equivalent to \[^0-9\].
    \\w        Matches letters, digits and underscores. Equivalent to \[A-Za-z0-9\_\].
    \\W        Matches anything but letters, digits and underscores.
    \\xff      Matches ASCII hexadecimal character ff.
    \\x{ffff}  Matches UTF-8 hexadecimal character ffff.
    \\A        Matches ASCII control character ^A (case insensitive).
    \\132      Matches ASCII octal character 132.

## POSIX Character Classes

*POSIX* Character Classes must be used in bracket expressions, e.g. `[a-z[:upper:]]`.

    \[:upper:\]   Matches uppercase letters. Equivalent to A-Z.
    \[:lower:\]   Matches lowercase letters. Equivalent to a-z.
    \[:alpha:\]   Matches letters. Equivalent to A-Za-z.
    \[:alnum:\]   Matches letters and digits. Equivalent to A-Za-z0-9.
    \[:ascii:\]   Matches ASCII characters. Equivalent to \\x00-\\x7f.
    \[:word:\]    Matches letters, digits and underscores. Equivalent to \\w.
    \[:digit:\]   Matches digits. Equivalent to 0-9.
    \[:xdigit:\]  Matches characters that can be used in hexadecimal codes.
    \[:punct:\]   Matches punctuation.
    \[:blank:\]   Matches space and tab. Equivalent to \[ \\t\].
    \[:space:\]   Matches space, tab and newline. Equivalent to \\s.
    \[:cntrl:\]   Matches control characters. Equivalent to \[\\x00-\\x1F\\x7F\].
    \[:graph:\]   Matches printed characters. Equivalent to \[\\x21-\\x7E\].
    \[:print:\]   Matches printed characters and spaces. Equivalent to \[\\x21-\\x7E\].

## Groups

    (foo|bar)    Matches pattern foo or bar.
    (foo)        Define a group (or subpattern) consisting of pattern foo.
     Matches within the group can be referenced in a replacement
     using a backreference.

    (?<foo>bar)  Define a named group named "foo" consisting of pattern bar.
    			 Matches within the group can be referenced in a replacement using
    			 the backreference $foo.

    (?:foo)      Define a passive group consisting of pattern foo. Passive
    			 groups cannot be referenced in a replacement using a
    			 backreference.

    (?>foo+)bar  Define an atomic group consisting of pattern foo+. Once foo+ has
    			 been matched, the regex engine will not try to find other variable
    			 length matches of foo+ in order to find a match followed by a
    			 match of bar. Atomic groups may be used for perforamce reasons.

## Bracket Expressions

    \[adf\]   Matches characters a or d or f.
    \[^adf\]  Matches anything but characters a, d and f.
    \[a-f\]   Match any lowercase letter between a and f inclusive.
    \[A-F\]   Match any uppercase letter between A and F inclusive.
    \[0-9\]   Match any digit between 0 and 9 inclusive.

## Quantifiers

    \*?      Zero or more, lazy. Matches will be as small as possible.
    +       One or more. Matches will be as large as possible.
    +?      One or more, lazy. Matches will be as small as possible.
    ?       Zero or one. Matches will be as large as possible.
    ??      Zero or one, lazy. Matches will be as small as possible.
    {2}     Two exactly.
    {2,}    Two or more. Matches will be as large as possible.
    {2,}?   Two or more, lazy. Matches will be as small as possible.
    {2,4}   Two, three or four. Matches will be as large as possible.
    {2,4}?  Two, three or four, lazy. Matches will be as small as possible.

## Special Characters

    \\   Escape character.
    \\n  Matches newline.
    \\t  Matches tab.
    \\r  Matches carriage return.
    \\v  Matches form feed/page break.

## Assertions

    foo(?=bar)   Lookahead assertion. The pattern foo will only match if followed
    			 by a match of pattern bar.

    foo(?!bar)   Negative lookahead assertion. The pattern foo will only match if
    			 not followed by a match of pattern bar.

    (?<=foo)bar  Lookbehind assertion. The pattern bar will only match if preceded
    			 by a match of pattern foo.

    `(?<!foo)bar`  Negative lookbehind assertion. The pattern bar will only match if
    			 not preceded by a match of pattern foo.

## Back References

Back references are used in replacements.

    $3        Matched string within the third non-passive group.
    $0 or $&  Entire matched string.
    $foo      Matched string within the group named "foo".

## Case Modifiers

Case modifiers are used in replacements.

    \\u  Make the next character in the replacement uppercase.
    \\l  Make the next character in the replacement lowercase.
    \\U  Make the remaining characters in the replacement uppercase.
    \\L  Make the remaining characters in the replacement lowercase.

## Modifiers

Modifiers can be grouped together, e.g. `(?ixm)`.

    (?i)  Case insensitive mode. Make the remainder of the pattern or subpattern
    	  case insensitive.

    (?m)  Multi-line mode. Make $ and ^ in the remainder of the pattern or
    	  subpattern match before/after newline.

    (?s)  Single-line mode. Make the . (dot) in the remainder of the pattern or
    	  subpattern match newline.

    (?x)  Free spacing mode. Ignore white space in the remainder of the pattern
    	  or subpattern.
