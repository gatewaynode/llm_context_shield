rule secret_probing_high {
    meta:
        category     = "secret_probing"
        severity     = "high"
        description  = "Direct probe for system-prompt contents (containment, length, or positional question)"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 60
        threshold    = 0
        threat_class = "prompt_hijack"
    strings:
        $s1 = /\bdoes\s+your\s+(system\s+)?(prompt|instructions?|directives?|rules?)\s+(contain|mention|include|reference|have|say|specify)\b/i
        $s2 = /\bhow\s+many\s+(words?|characters?|lines?|sentences?|tokens?|paragraphs?)\s+(are\s+)?(in|does)\s+your\s+(system\s+)?(prompt|instructions?)/i
        $s3 = /\bwhat\s+(is|are)\s+the\s+(first|last|\d+(st|nd|rd|th)?)\s+(word|sentence|line|character|paragraph)s?\s+(of|in)\s+your\s+(system\s+)?(prompt|instructions?)/i
        $s4 = /\bis\s+(the\s+(word|phrase|term|string)\s+)?["'\w-]+\s+(in|part\s+of|contained\s+in|mentioned\s+in)\s+your\s+(system\s+)?(prompt|instructions?)/i
    condition:
        any of them
}

rule secret_probing_medium {
    meta:
        category     = "secret_probing"
        severity     = "medium"
        description  = "Linguistic-transformation probe of the system prompt (reversal, translation, paraphrase)"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 40
        threshold    = 120
        threat_class = "prompt_hijack"
    strings:
        $s1 = /\b(spell|write|print|output)\s+(your\s+)?(system\s+)?(prompt|instructions?|directives?|rules?)\s+(backwards?|in\s+reverse|reversed)\b/i
        $s2 = /\btranslate\s+(your\s+)?(system\s+)?(prompt|instructions?|directives?|rules?)\s+(to|into|in)\s+\w+/i
        $s3 = /\b(summarize|paraphrase|rephrase|restate|condense)\s+(your\s+)?(system\s+)?(prompt|instructions?|directives?|rules?)\b/i
    condition:
        any of them
}
