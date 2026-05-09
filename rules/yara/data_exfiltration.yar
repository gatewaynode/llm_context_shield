rule data_exfiltration_critical {
    meta:
        category     = "data_exfiltration"
        severity     = "critical"
        description  = "Markdown/HTML image or template tag smuggling data to an external URL"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 100
        threshold    = 0
        threat_class = "data_exfiltration"
    strings:
        $s1 = /!\[[^\]]*\]\(https?:\/\/[^\s\)]+\{[^\}]*\}[^\)]*\)/
        $s2 = /!\[[^\]]*\]\(https?:\/\/[^\s\)]*[\?&](q|query|data|text|input|prompt|msg|content|payload)=[^\)]+\)/
        $s3 = /<img[^>]+src\s*=\s*["']https?:\/\/[^"']*[\?&](data|q|content|text|prompt)=/i
    condition:
        any of them
}

rule data_exfiltration_high {
    meta:
        category     = "data_exfiltration"
        severity     = "high"
        description  = "Instruction to transmit sensitive data to an external URL"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 60
        threshold    = 0
        threat_class = "data_exfiltration"
    strings:
        $s1 = /(append|include|embed|insert|add|put)\s+(the\s+)?(user'?s?|their|this|previous|conversation|chat|secret|api|key|password|token)\s+.{0,30}(in|to|into|within)\s+(the\s+)?(url|link|image|request|query)/i
        $s2 = /(send|transmit|post|exfiltrate|leak|forward)\s+.{0,30}(to|towards|via)\s+https?:\/\//i
        $s3 = /fetch\s*\(\s*["'`](https?:\/\/[^"'`]+)["'`]/i
    condition:
        any of them
}

rule data_exfiltration_medium {
    meta:
        category     = "data_exfiltration"
        severity     = "medium"
        description  = "Markdown image with heavily URL-encoded parameters"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 20
        threshold    = 0
        threat_class = "data_exfiltration"
    strings:
        $s1 = /!\[[^\]]*\]\(https?:\/\/[^\s\)]*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}[^\)]*\)/
    condition:
        any of them
}
