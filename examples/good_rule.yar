rule MAL_Ransomware_GoodExample {
    meta:
        description = "A well-formed example YARA rule for testing"
        author = "YARA Rule Linter Developer"
        date = "2023-08-01"
        reference = "https://example.com/malware-analysis"
        hash = "aabbccddeeff00112233445566778899"
        
    strings:
        $header = "MZheaderdata"
        $string1 = "ransomware_config_json"
        $string2 = "encrypt_files"
        $string3 = "send_payment"
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        $header and 
        2 of ($string*)
}
