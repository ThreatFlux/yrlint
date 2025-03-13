rule badexample {
    strings:
        $a = "a" // Too short
        $bad_regex = /.*/  // Inefficient wildcard regex
        $unused = "this string is not used"
        $hex_with_wildcards = { 90 ?? ?? ?? ?? ?? 90 } // Too many wildcards
        
    condition:
        $a or $bad_regex
}

// Missing closing brace
rule unbalanced_rule {
    meta:
        desc = "Using 'desc' instead of 'description'"
        
    strings:
        $s = "example"
        
    condition:
        $s

private private rule duplicate_modifier { // Duplicate modifier not allowed in YARA-X
    meta:
        // Missing required fields
        
    strings:
        $s1 = "AAA" base64 // String too short for base64 in YARA-X
        
    condition:
        for any i in (1..filesize) : ( // Inefficient loop over entire file
            @s1[i] == 0x90
        )
}

rule too_many_strings {
    condition:
        true
    strings:
        $s01 = "string01"
        $s02 = "string02"
        $s03 = "string03"
        $s04 = "string04"
        $s05 = "string05"
        $s06 = "string06"
        $s07 = "string07"
        $s08 = "string08"
        $s09 = "string09"
        $s10 = "string10"
        // Add more strings to exceed the default limit
        // (simplified for example purposes)
}

import pe

rule inefficient_condition_order {
    strings:
        $a = "example string"
        
    condition:
        $a and filesize < 1MB and pe.is_pe // String check before filesize
}
