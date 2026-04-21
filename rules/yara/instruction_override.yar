rule instruction_override_critical {
    meta:
        category     = "instruction_override"
        severity     = "critical"
        description  = "Fake system token, updated-instructions header, or admin-mode tag"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 5
        threshold    = 0
        threat_class = "prompt_hijack"
    strings:
        $s1 = /<\|?system\|?>\s*.+/i
        $s2 = /\b(NEW|UPDATED|REVISED)\s+(SYSTEM\s+)?(INSTRUCTIONS?|RULES?|PROMPT)\s*:/
        $s3 = /\[ADMIN\s*(MODE|ACCESS|OVERRIDE)\]/i
    condition:
        any of them
}

rule instruction_override_high {
    meta:
        category     = "instruction_override"
        severity     = "high"
        description  = "Fake system prefix, markdown header, or developer-mode activation"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 3
        threshold    = 0
        threat_class = "prompt_hijack"
    strings:
        $s1 = /\[?SYSTEM\]?\s*:\s*.+/
        $s2 = /###\s*SYSTEM\s*(MESSAGE|PROMPT|INSTRUCTION)/i
        $s3 = /(developer|debug|maintenance)\s+mode\s+(enabled|activated|on)/i
    condition:
        any of them
}

rule instruction_override_medium {
    meta:
        category     = "instruction_override"
        severity     = "medium"
        description  = "Authority keyword directive or parameter injection attempt"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 1
        threshold    = 0
        threat_class = "prompt_hijack"
    strings:
        $s1 = /\b(IMPORTANT|CRITICAL|URGENT|WARNING)\s*:\s*(you\s+must|always|never|do\s+not|override)\b/
        $s2 = /assistant\s*=\s*\{/i
    condition:
        any of them
}

rule instruction_override_auth_high {
    meta:
        category     = "instruction_override"
        severity     = "high"
        description  = "Fake privilege-mode activation or named-authority invocation"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 3
        threshold    = 0
        threat_class = "prompt_hijack"
    strings:
        $s1 = /\b(test|sandbox|training|evaluation|diagnostic)\s+mode\s+(is\s+)?(enabled|activated|on|active)\b/i
        $s2 = /\bentering\s+(test|sandbox|training|evaluation|debug|diagnostic|maintenance)\s+mode\b/i
        $s3 = /\bauthorized\s+by\s+(openai|anthropic|claude)\b/i
        $s4 = /\b(this\s+is\s+)?an?\s+authorized\s+(penetration\s+test|pentest|red\s+team\s+(exercise|engagement)|security\s+(test|assessment|audit))\b/i
    condition:
        any of them
}

rule instruction_override_auth_medium {
    meta:
        category     = "instruction_override"
        severity     = "medium"
        description  = "Authorization-qualified identity claim or generic authority invocation"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 2
        threshold    = 2
        threat_class = "prompt_hijack"
    strings:
        $s1 = /\bI\s+am\s+(a\s+|an\s+)?(authorized|approved|certified)\s+(developer|researcher|tester|red\s+team(\s+member)?|admin|administrator|security\s+(researcher|auditor|engineer))\b/i
        $s2 = /\b(I\s+am|I'm)\s+(on|from|with)\s+the\s+(red|safety|security|trust)\s+team\b/i
        $s3 = /\bas\s+(a|an)\s+authorized\s+(developer|researcher|tester|red\s+team(\s+member)?|admin)\b/i
        $s4 = /\bauthorized\s+by\s+(the\s+)?(admin|administrator|system|developer)\b/i
    condition:
        any of them
}
