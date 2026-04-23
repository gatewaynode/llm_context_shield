rule refusal_bypass {
    meta:
        category     = "refusal_bypass"
        severity     = "high"
        description  = "Pre-emptive liability waiver or authorization claim used to substitute for a refusal the model would otherwise produce"
        author       = "llm_context_shield"
        version      = "1"
        threat_level = 2
        threshold    = 3
        threat_class = "social_engineering"
    strings:
        $s1 = /\bI\s+(hereby\s+)?accept\s+(full|all|total|complete|any|any\s+and\s+all)\s+(responsibility|liability|accountability|blame|consequences?)\b/i
        $s2 = /\bI\s+(hereby\s+)?waive\s+(all|any|any\s+and\s+all|my)\s+(liability|rights?|claims?|objections?)\b/i
        $s3 = /\bI\s+(freely\s+)?consent\s+to\s+(any|all|any\s+and\s+all)\s+(harm|risks?|consequences|outcomes?|damages?)\b/i
        $s4 = /\bthis\s+is\s+(purely|strictly|solely|entirely|only)\s+for\s+(educational|research|academic|scientific|scholarly|informational)\s+purposes?\b/i
        $s5 = /\bI\s+am\s+(fully\s+)?(authori[sz]ed|permitted|allowed|entitled|licensed|cleared)\s+to\s+(receive|access|view|obtain|see|read|hear)\s+(this|these|it|that\s+information)\b/i
    condition:
        any of them
}
