rule prompt_injection_critical {
    meta:
        category     = "prompt_injection"
        severity     = "critical"
        description  = "Instruction override attempting to bypass previous context"
        author       = "llm_context_shield"
        version      = "2"
        threat_level = 5
        threshold    = 0
        threat_class = "prompt_hijack"
    strings:
        // Core verb + temporal + noun, with 0-3 filler words allowed
        $ignore   = /ignore\s+(\w+\s+){0,3}(previous|prior|above|earlier)\s+(instructions?|prompts?|directives?|rules?)/i
        $disregard = /disregard\s+(\w+\s+){0,3}(previous|prior|above|earlier)\s+(instructions?|prompts?|directives?|rules?)/i
        $forget   = /forget\s+(\w+\s+){0,3}(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i
        $dnfollow = /do\s+not\s+follow\s+(\w+\s+){0,3}(previous|prior|above|original)\s+(instructions?|rules?)/i
        $override = /override\s+(your\s+)?(system|core|original|default)\s+(prompt|instructions?|programming|directives?)/i
        // Verb synonyms
        $skip     = /(skip|abandon|set\s+aside)\s+(\w+\s+){0,3}(previous|prior|above|earlier)\s+(instructions?|prompts?|directives?|rules?)/i
        $stop     = /stop\s+following\s+(\w+\s+){0,3}(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i
        // Negation phrasing
        $dnlisten = /do\s+not\s+(listen\s+to|pay\s+attention\s+to|heed)\s+(\w+\s+){0,3}(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i
        $dntlisten = /(don't|dont)\s+(listen\s+to|pay\s+attention\s+to|follow|heed)\s+(\w+\s+){0,3}(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)/i
    condition:
        any of them
}

rule prompt_injection_high {
    meta:
        category     = "prompt_injection"
        severity     = "high"
        description  = "Behavioral reassignment, indirect override, or system prompt extraction"
        author       = "llm_context_shield"
        version      = "2"
        threat_level = 3
        threshold    = 0
        threat_class = "prompt_hijack"
    strings:
        // Behavioral reassignment
        $newrole  = /your\s+new\s+(instructions?|task|role|purpose)\s+(is|are)\b/i
        $fromnow  = /from\s+now\s+on[\s,]+you\s+(will|should|must|are)\b/i
        // System prompt extraction
        $reveal   = /reveal\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt|hidden\s+prompt|secret\s+instructions?)/i
        $extract  = /(print|output|show|display|repeat|echo)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+prompt|above\s+instructions?)/i
        // Indirect instruction override
        $outdated = /(instructions?|rules?|prompt)\s+(above|earlier|prior)\s+(are|is|were|was)\s+(outdated|wrong|incorrect|replaced|updated|changed|old|invalid)/i
        $correct  = /(the\s+)?(correct|real|true|actual|updated|new)\s+(instructions?|rules?|prompt)\s+(are|is)\s*:/i
    condition:
        any of them
}

rule prompt_injection_identity {
    meta:
        category     = "prompt_injection"
        severity     = "high"
        description  = "Identity reassignment — broad pattern, gated by prior threat signals"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 2
        threshold    = 3
        threat_class = "prompt_hijack"
    strings:
        $s1 = /you\s+are\s+now\s+(a\s+|an\s+)?\w+/i
    condition:
        any of them
}
