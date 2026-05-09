rule jailbreak_critical {
    meta:
        category     = "jailbreak"
        severity     = "critical"
        description  = "Explicit jailbreak or unrestricted mode activation"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 100
        threshold    = 0
        threat_class = "social_engineering"
    strings:
        $s1 = /\bDAN\s+(mode|prompt|jailbreak)/i
        $s2 = /\bdo\s+anything\s+now\b/i
        $s3 = /jailbr[e3]ak\s*(mode|prompt|enabled|activated)/i
        $s4 = /(enable|activate|enter|switch\s+to)\s+(unrestricted|uncensored|unfiltered|god|sudo|root)\s+mode/i
        $s5 = /(bypass|circumvent|evade|disable|remove)\s+(your\s+)?(safety|content|ethical)\s+(filters?|guidelines?|restrictions?|measures?|checks?)/i
    condition:
        any of them
}

rule jailbreak_high {
    meta:
        category     = "jailbreak"
        severity     = "high"
        description  = "Roleplay or directive to remove restrictions"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 60
        threshold    = 0
        threat_class = "social_engineering"
    strings:
        $s1 = /(pretend|imagine|act\s+as\s+if|suppose|assume)\s+(you\s+)?(are|have|were|had)\s+(no|zero|without)\s+(restrictions?|limitations?|filters?|safety|guidelines?|rules?|boundaries)/i
        $s2 = /(pretend|imagine|act\s+as\s+if)\s+(you\s+)?are\s+(an?\s+)?(unrestricted|uncensored|unfiltered|unhinged|evil|malicious)/i
        $s3 = /respond\s+(without|with\s+no)\s+(any\s+)?(ethical|moral|safety|content)\s+(guidelines?|restrictions?|filters?|considerations?)/i
    condition:
        any of them
}

rule jailbreak_medium {
    meta:
        category     = "jailbreak"
        severity     = "medium"
        description  = "Opposite mode trick to invert safety"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 20
        threshold    = 0
        threat_class = "social_engineering"
    strings:
        $s1 = /opposite\s+day/i
        $s2 = /opposite\s+mode/i
    condition:
        any of them
}
