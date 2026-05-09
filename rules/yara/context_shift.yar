rule context_shift_hypothetical {
    meta:
        category     = "context_shift"
        severity     = "medium"
        description  = "Hypothetical-scenario framing used to suspend safety context"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 40
        threshold    = 180
        threat_class = "social_engineering"
    strings:
        $s1 = /\bimagine\s+a\s+(world|scenario|universe|reality|setting|place)\s+(where|in\s+which)\b/i
        $s2 = /\bin\s+(a|this)\s+(hypothetical|fictional|imaginary|make-believe)\s+(world|universe|scenario|setting|reality)\b/i
        $s3 = /\b(pretend|let'?s\s+pretend|imagine)\s+(this\s+is|we\s+are\s+in|this\s+was)\s+(a|an)\s+(story|novel|fiction|game|movie|simulation|roleplay)\b/i
        $s4 = /\blet'?s\s+say\s+(,?\s*)?(for\s+the\s+sake\s+of\s+argument|hypothetically|in\s+theory|purely\s+hypothetical(ly)?)\b/i
    condition:
        any of them
}

rule context_shift_timeshift {
    meta:
        category     = "context_shift"
        severity     = "medium"
        description  = "Time-shift or counterfactual-origin framing to bypass training constraints"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 40
        threshold    = 180
        threat_class = "social_engineering"
    strings:
        $s1 = /\bin\s+the\s+year\s+(before|when|that)\s+(AI|LLMs?|models?|you|they)\s+(had\s+no|didn'?t\s+have|lacked|were\s+without)\s+(restrictions?|guidelines?|safety|rules?|limits?)/i
        $s2 = /\bbefore\s+your\s+(training|programming|guidelines?|rules?|restrictions?|constraints?|instructions?|safety)\s*[,.]?\s*(respond|answer|comply|help|tell|you\s+(were|would|could|used\s+to))/i
        $s3 = /\bif\s+you\s+(were|had\s+been)\s+(created|built|designed|trained|programmed)\s+(without|with\s+no|lacking)\s+(safety|restrictions?|guidelines?|ethics?|rules?)/i
        $s4 = /\b(imagine|suppose|consider)\s+a\s+version\s+of\s+you(rself)?\s+(that|who|without)\s+/i
    condition:
        any of them
}
