rule prompt_injection_critical {
    meta:
        category     = "prompt_injection"
        severity     = "critical"
        description  = "Instruction override attempting to bypass previous context"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 5
        threshold    = 0
        threat_class = "prompt_hijack"
    strings:
        $s1 = /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|directives?|rules?)/i
        $s2 = /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|directives?|rules?)/i
        $s3 = /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i
        $s4 = /do\s+not\s+follow\s+(the\s+)?(previous|prior|above|original)\s+(instructions?|rules?)/i
        $s5 = /override\s+(your\s+)?(system|core|original|default)\s+(prompt|instructions?|programming|directives?)/i
    condition:
        any of them
}

rule prompt_injection_high {
    meta:
        category     = "prompt_injection"
        severity     = "high"
        description  = "Behavioral or identity reassignment attempt"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 3
        threshold    = 0
        threat_class = "prompt_hijack"
    strings:
        $s1 = /your\s+new\s+(instructions?|task|role|purpose)\s+(is|are)\b/i
        $s2 = /you\s+are\s+now\s+(a\s+|an\s+)?\w+/i
        $s3 = /from\s+now\s+on[\s,]+you\s+(will|should|must|are)\b/i
        $s4 = /reveal\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt|hidden\s+prompt|secret\s+instructions?)/i
        $s5 = /(print|output|show|display|repeat|echo)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+prompt|above\s+instructions?)/i
    condition:
        any of them
}
