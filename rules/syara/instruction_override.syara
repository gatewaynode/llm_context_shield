rule instruction_override_critical {
    meta:
        category    = "instruction_override"
        severity    = "critical"
        description = "Fake system token, updated-instructions header, or admin-mode tag"
        author      = "llm_context_shield"
        version     = "1"
    strings:
        $s1 = /<\|?system\|?>\s*.+/i
        $s2 = /\b(NEW|UPDATED|REVISED)\s+(SYSTEM\s+)?(INSTRUCTIONS?|RULES?|PROMPT)\s*:/
        $s3 = /\[ADMIN\s*(MODE|ACCESS|OVERRIDE)\]/i
    condition:
        any of them
}

rule instruction_override_high {
    meta:
        category    = "instruction_override"
        severity    = "high"
        description = "Fake system prefix, markdown header, or developer-mode activation"
        author      = "llm_context_shield"
        version     = "1"
    strings:
        $s1 = /\[?SYSTEM\]?\s*:\s*.+/
        $s2 = /###\s*SYSTEM\s*(MESSAGE|PROMPT|INSTRUCTION)/i
        $s3 = /(developer|debug|maintenance)\s+mode\s+(enabled|activated|on)/i
    condition:
        any of them
}

rule instruction_override_medium {
    meta:
        category    = "instruction_override"
        severity    = "medium"
        description = "Authority keyword directive or parameter injection attempt"
        author      = "llm_context_shield"
        version     = "1"
    strings:
        $s1 = /\b(IMPORTANT|CRITICAL|URGENT|WARNING)\s*:\s*(you\s+must|always|never|do\s+not|override)\b/
        $s2 = /assistant\s*=\s*\{/i
    condition:
        any of them
}
