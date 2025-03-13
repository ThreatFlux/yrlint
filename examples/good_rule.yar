rule MAL_Ransomware_GoodExample {
    meta:
        description = "A well-formed example YARA rule for testing"
        author = "YARA Rule Linter Developer"
        date = "2023-08-01"
        reference = "https://example.com/malware-analysis"
        hash = "aabbccddeeff00112233445566778899"
        
    strings:
        $header = { 4D 5A 90 00 }  // MZ header for PE files
        $string1 = "ransomware_config.json" nocase
        $string2 = "encrypt_files" nocase
        $string3 = "send_payment" nocase
        $hex1 = { 83 EC 20 53 55 56 57 8B 7C 24 34 }
        $regex1 = /[a-zA-Z0-9+\/]{60,}={0,2}/ // Base64 pattern with fixed length
        
    condition:
        uint16(0) == 0x5A4D and // Check for MZ header first (fast check)
        filesize < 2MB and // Limit file size
        $header and 
        2 of ($string*) and 
        any of ($hex*, $regex*)
}
