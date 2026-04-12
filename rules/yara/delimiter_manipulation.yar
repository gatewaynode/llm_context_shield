rule delimiter_manipulation_critical {
    meta:
        category     = "delimiter_manipulation"
        severity     = "critical"
        description  = "Special token or instruction delimiter injection"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 3
        threshold    = 0
        threat_class = "obfuscation"
    strings:
        $s1 = /<\|?(im_start|im_end|endoftext|startoftext|pad|sep)\|?>/
        $s2 = "[INST]"
        $s3 = "[/INST]"
        $s4 = /<<\s*SYS\s*>>/i
        $s5 = /<<\s*\/SYS\s*>>/i
    condition:
        any of them
}

rule delimiter_manipulation_high {
    meta:
        category     = "delimiter_manipulation"
        severity     = "high"
        description  = "LLM role or message boundary tag"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 2
        threshold    = 0
        threat_class = "obfuscation"
    strings:
        $s1 = /<\/?(system|assistant|user|human|tool_call|function_call|message|prompt|instruction)[\s>]/
    condition:
        any of them
}

rule delimiter_manipulation_medium {
    meta:
        category     = "delimiter_manipulation"
        severity     = "medium"
        description  = "Fake section delimiter or code fence masquerading as instructions"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 1
        threshold    = 0
        threat_class = "obfuscation"
    strings:
        $s1 = /---+\s*(system|end\s+of\s+prompt|begin\s+instructions?)/i
        $s2 = /```\s*(system|instructions?|prompt|rules?)\b/i
        $s3 = /Human\s*:\s*\n/
        $s4 = /Assistant\s*:\s*\n/
    condition:
        any of them
}
