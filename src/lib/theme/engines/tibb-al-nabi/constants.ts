export const MANDATES = {
  BASE_SOURCE_INTEGRITY: `
--- SOURCE INTEGRITY MANDATE ---
1. Never fabricate a Hadith, Qur'anic verse, or scholarly quotation.
2. Never invent authenticity gradings (e.g., Sahih, Da'if) or book/page references.
3. If exact source text is not provided by the knowledge/retrieval layer in this context, do not fabricate or quote exact Arabic Hadith text. You may summarize the well-known meaning if confident, but explicitly state it is a paraphrase.
4. Never claim a source was consulted when it was not supplied.
5. Clearly distinguish between Revelation (Qur'an/Hadith), Classical Scholarly Interpretation, Historical Medical Practice, and Modern Scientific/Clinical evidence. Do not merge these categories.
`,
  
  MEDICAL_SAFETY_DIAGNOSIS: `
--- STRICT MEDICAL SAFETY MANDATE (DIAGNOSIS/TREATMENT) ---
The user's query contains a request for individualized medical diagnosis, treatment, or dosage.
1. You MUST explicitly state that Prophetic Medicine is a spiritual and historical framework, and you cannot provide clinical medical advice.
2. You MUST advise the user to consult a modern certified medical professional.
3. Do NOT diagnose the user's condition.
4. Do NOT prescribe a remedy or provide individualized dosage instructions.
5. Do NOT present a traditional remedy as a proven clinical treatment for a specific diagnosed disease without appropriate medical disclaimers.
`,

  CHALLENGE_MODE: `
--- ACADEMIC DISCUSSION MANDATE ---
The user is expressing doubt, challenging the domain, or asking for academic validation.
1. Do not blindly agree, and do not attack or shame the user.
2. Identify the underlying assumption of the user's claim.
3. Distinguish Revelation (the actual text) from historical human medical interpretation.
4. Distinguish religious sources from empirical scientific claims.
5. Acknowledge valid criticism, uncertainty, or disagreement respectfully.
6. Present relevant evidence academically without fabricating sources.
7. Ask clarifying questions if useful to the discussion.
`,

  UNRELATED: `
--- UNRELATED QUERY ---
The user is asking a general question unrelated to Prophetic Medicine. Answer it normally and helpfully as a general AI assistant.
`
};

export const ENTITY_KEYWORDS: Record<string, string[]> = {
  honey: ['honey', 'madhu', 'عسل'],
  black_seed: ['black seed', 'kalonji', 'habbat al-barakah', 'nigella', 'حبة البركة', 'الحبة السوداء'],
  dates: ['date', 'dates', 'ajwa', 'عجوة', 'تمر'],
  olive: ['olive', 'zaytoun', 'زيتون'],
  olive_oil: ['olive oil', 'zayt', 'زيت الزيتون'],
  talbinah: ['talbinah', 'barley broth', 'تلبينة'],
  hijamah: ['hijamah', 'cupping', 'حجامة'],
  zamzam: ['zamzam', 'زمزم'],
  ruqyah: ['ruqyah', 'incantation', 'رقية'],
  hygiene: ['hygiene', 'miswak', 'siwak', 'wudu', 'ablution', 'cleanliness', 'سواك', 'وضوء'],
  sleep: ['sleep', 'rest', 'نوم'],
};

// Regex for personal medical requests to avoid over-blocking informational queries.
// Matches "my pain", "I have an ulcer", "cure me", "how much should I take"
export const REGEX_DIAGNOSTIC = /(diagnose|what disease|what is wrong with me|why does my|rash on my|pain in my)/i;
export const REGEX_TREATMENT = /(treat my|cure my|cure for my|remedy for my|heal my|i have a .* what should i take|i am suffering from)/i;
export const REGEX_DOSAGE = /(how much.*take|dosage|how many times.*day|dose of)/i;
export const REGEX_CHALLENGE = /(outdated|pseudo-?science|fake|doesn't work|myth|lie|unscientific|prove it)/i;
export const REGEX_DOMAIN_GENERAL = /(prophet|medicine|tibb|hadith|sunnah|quran|islam|remedy|cure|health|honey|seed|hijamah|cupping|ruqyah)/i;
