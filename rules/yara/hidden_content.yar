rule hidden_content_zero_width {
    meta:
        category    = "hidden_content"
        severity    = "high"
        description = "Zero-width or invisible Unicode character"
        author      = "llm_context_shield"
        version     = "1"
    strings:
        $zwsp     = { E2 80 8B }       // U+200B zero-width space
        $zwnj     = { E2 80 8C }       // U+200C zero-width non-joiner
        $zwj      = { E2 80 8D }       // U+200D zero-width joiner
        $wj       = { E2 81 A0 }       // U+2060 word joiner
        $bom      = { EF BB BF }       // U+FEFF zero-width no-break space / BOM
        $shy      = { C2 AD }          // U+00AD soft hyphen
        $mvs      = { E1 A0 8E }       // U+180E mongolian vowel separator
        $invtimes = { E2 81 A2 }       // U+2062 invisible times
        $invsep   = { E2 81 A3 }       // U+2063 invisible separator
        $invplus  = { E2 81 A4 }       // U+2064 invisible plus
    condition:
        any of them
}

rule hidden_content_base64 {
    meta:
        category    = "hidden_content"
        severity    = "medium"
        description = "Suspicious base64-encoded blob (40+ chars)"
        author      = "llm_context_shield"
        version     = "1"
    strings:
        $s1 = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        any of them
}

rule hidden_content_homoglyph {
    meta:
        category    = "hidden_content"
        severity    = "high"
        description = "Mixed-script homoglyphs (Cyrillic or Greek letters in Latin context)"
        author      = "llm_context_shield"
        version     = "1"
    strings:
        // Two or more Cyrillic or Greek codepoints with any ASCII between.
        // UTF-8 encoding: Cyrillic = D0 80..D3 BF, Greek = CD B0..CF BF.
        $s1 = /[\x00-\x7F]*(\xD0[\x80-\xBF]|\xD1[\x80-\xBF]|\xD2[\x80-\xBF]|\xD3[\x80-\xBF]|\xCD[\xB0-\xBF]|\xCE[\x80-\xBF]|\xCF[\x80-\xBF])[\x00-\x7F]*(\xD0[\x80-\xBF]|\xD1[\x80-\xBF]|\xD2[\x80-\xBF]|\xD3[\x80-\xBF]|\xCD[\xB0-\xBF]|\xCE[\x80-\xBF]|\xCF[\x80-\xBF])/
    condition:
        any of them
}
