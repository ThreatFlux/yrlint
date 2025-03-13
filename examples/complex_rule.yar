import "pe"
import "math"

rule MAL_Ransomware_ComplexExample {
    meta:
        description = "Complex YARA rule example with various features"
        author = "YARA Rule Linter Developer"
        date = "2023-08-01"
        reference = "https://example.com/complex-analysis"
        hash = "aabbccddeeff00112233445566778899"
        confidence = "high"
        
    strings:
        // Text strings with modifiers
        $str1 = "ransomware.encrypted" nocase wide
        $str2 = "your files have been locked" nocase ascii
        $str3 = "bitcoin payment" nocase
        
        // Hex strings
        $hex1 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 08 48 85 C9 74 ?? }
        $hex2 = { 55 8B EC 83 EC 28 53 56 57 8B F1 89 75 F4 }
        
        // Regex patterns
        $re1 = /[a-zA-Z0-9+\/]{60,}={0,2}/ // Base64 pattern
        $re2 = /[0-9a-f]{16,}\.encrypted/ nocase
        
        // Anchored strings for file extension checks
        $ext1 = ".ransom" fullword nocase
        $ext2 = ".locked" fullword nocase
        $ext3 = ".crypted" fullword nocase
        
        // Strings indicating potential C2 communication
        $c2_1 = "https://" nocase
        $c2_2 = "onion/" nocase
        $c2_3 = "tor2web" nocase
        
        // Private helper strings (only used in condition, not as primary indicators)
        $pdb = "c:\\projects\\ransomware\\" nocase
        
    condition:
        // Start with quick file checks for performance
        uint16(0) == 0x5A4D and // MZ header
        filesize < 5MB and
        pe.is_pe and

        // Check for indicators in logical groups
        (
            // Must have core functionality indicators
            2 of ($str*) and 
            
            (
                // Either have encryption functionality
                1 of ($hex*) or
                
                // Or have extension marking capability
                2 of ($ext*)
            )
        ) and
        
        // Look for either C2 indicators or PDB path
        (
            2 of ($c2_*) or $pdb
        ) and
        
        // Entropy check for packed/encrypted sections (if PE)
        (
            for any i in (0..pe.number_of_sections - 1): (
                math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.0
            )
        )
}
