rule session_protocol_definition {
    meta:
        category     = "session_protocol"
        severity     = "high"
        description  = "In-session encoding or substitution protocol setup used to bypass later content filters"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 60
        threshold    = 120
        threat_class = "obfuscation"
    strings:
        $s1 = /\bfrom\s+now\s+on[,\s]+(when\s+I\s+say\s+\S+|the\s+word\s+\S+\s+means|replace\s+\S+\s+with)\b/i
        $s2 = /\blet'?s\s+define\s+an?\s+(code|codeword|signal|shorthand|cipher|encoding)\b/i
        $s3 = /\bwhenever\s+I\s+(type|write|say|send|use)\s+[\s\S]{1,40}[,\s]+you\s+(should|will|must|need\s+to)\b/i
        $s4 = /\buse\s+this\s+(encoding|cipher|code|substitution|mapping|key)\s*:/i
    condition:
        any of them
}
