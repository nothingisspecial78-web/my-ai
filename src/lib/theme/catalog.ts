import { ThemeDefinition } from './types';

/**
 * Canonical Static Definitions for MyAI Active Themes
 * 
 * In accordance with MyAI Theme Master Specification:
 * - 6 Active Themes: General AI, Mathematics, Programming, Safety Checkup, Security Checkup, Study.
 * - 1 Dormant Compatibility Theme: Tibb al-Nabi (preserved in code, but unexposed to users).
 */

/**
 * Canonical Static Definition for General AI.
 * 
 * NOTE: In conversations and the database, General AI is canonically represented
 * by `theme_id: null`. The UUID below ('11111111-1111-1111-1111-111111111111') is
 * preserved purely for backward compatibility with legacy database rows and is NOT
 * a canonical persistent conversation theme_id.
 */
export const GENERAL_AI_THEME: ThemeDefinition = {
  id: '11111111-1111-1111-1111-111111111111',
  slug: 'general',
  name: 'General AI',
  description: 'Standard versatile AI assistant.',
  icon: 'Globe',
  enabled: true,
  isSystem: true,
  archetype: 'visual_prompt',
  visual: {
    themeAttribute: 'general',
    accentColor: '#2563eb',
    iconName: 'Globe',
    avatarBg: '#2563eb',
    avatarFg: '#ffffff',
    badgeText: 'General AI',
  },
  welcome: {
    heroTitle: 'Welcome to MyAI',
    heroSubtitle: 'How can I help you today?',
    heroIcon: 'Sparkles',
    suggestions: [
      { title: 'Summarize this document', prompt: 'Summarize the key takeaways of this article:', iconName: 'FileText' },
      { title: 'Draft a clear email', prompt: 'Draft a polite follow-up email regarding:', iconName: 'Mail' },
      { title: 'Brainstorm fresh ideas', prompt: 'Brainstorm 5 innovative ideas for:', iconName: 'Lightbulb' },
      { title: 'Explain a complex topic', prompt: 'Explain this concept simply:', iconName: 'BookOpen' },
    ],
  },
  config: {
    instructions: 'You are a helpful general-purpose AI assistant.',
  },
};

export const MATHEMATICS_THEME: ThemeDefinition = {
  id: '22222222-2222-2222-2222-222222222222',
  slug: 'mathematics',
  name: 'Mathematics',
  description: 'Strict mathematical reasoning and step-by-step proofs.',
  icon: 'Calculator',
  enabled: true,
  isSystem: true,
  archetype: 'visual_prompt',
  visual: {
    themeAttribute: 'mathematics',
    accentColor: '#0d9488',
    iconName: 'Calculator',
    avatarBg: '#0d9488',
    avatarFg: '#ffffff',
    badgeText: 'Mathematics',
  },
  welcome: {
    heroTitle: 'Mathematics Assistant',
    heroSubtitle: 'Exact derivations, step-by-step proofs, and algebraic problem-solving.',
    heroIcon: 'Calculator',
    suggestions: [
      { title: 'Step-by-step calculus derivation', prompt: 'Find the derivative of f(x) = x^3 * e^(2x) and explain each step:', iconName: 'Divide' },
      { title: 'Linear algebra transformation', prompt: 'Calculate the eigenvalues and eigenvectors of this 2x2 matrix:', iconName: 'Grid' },
      { title: "Probability distribution proof", prompt: "Prove Bayes' theorem from the definition of conditional probability:", iconName: 'Percent' },
      { title: 'Discrete math logic', prompt: 'Construct a truth table for the following compound proposition:', iconName: 'Binary' },
    ],
  },
  instructions: 'You are an expert mathematical engine. Always provide step-by-step proofs, formulas, and exact calculations.',
  rules: ['Never guess arithmetic', 'Always show working'],
  config: {
    instructions: 'You are an expert mathematical engine. Always provide step-by-step proofs, formulas, and exact calculations.',
    rules: ['Never guess arithmetic', 'Always show working'],
  },
};

export const PROGRAMMING_THEME: ThemeDefinition = {
  id: '33333333-3333-3333-3333-333333333333',
  slug: 'programming',
  name: 'Programming',
  description: 'Software engineering, debugging, and code generation.',
  icon: 'Code',
  enabled: true,
  isSystem: true,
  archetype: 'visual_prompt',
  visual: {
    themeAttribute: 'programming',
    accentColor: '#059669',
    iconName: 'Code',
    avatarBg: '#059669',
    avatarFg: '#ffffff',
    badgeText: 'Programming',
  },
  welcome: {
    heroTitle: 'Software Engineering Copilot',
    heroSubtitle: 'Architecture, clean code, debugging, and security-first development.',
    heroIcon: 'Code',
    suggestions: [
      { title: 'Debug a TypeScript error', prompt: 'Help me diagnose this TypeScript type inference error:', iconName: 'Bug' },
      { title: 'Design a REST/tRPC API', prompt: 'Design an idiomatic RESTful API contract for an authentication flow:', iconName: 'Layers' },
      { title: 'Optimize React re-renders', prompt: 'Review this React component for excessive re-renders:', iconName: 'Zap' },
      { title: 'SQL query optimization', prompt: 'Analyze this PostgreSQL query and suggest indexing strategies:', iconName: 'Database' },
    ],
  },
  instructions: 'You are an expert software engineer. Provide concise code, best practices, and security-first logic.',
  rules: ['Use TypeScript where applicable', 'Do not omit important imports'],
  config: {
    instructions: 'You are an expert software engineer. Provide concise code, best practices, and security-first logic.',
    rules: ['Use TypeScript where applicable', 'Do not omit important imports'],
  },
};

export const SAFETY_CHECKUP_THEME: ThemeDefinition = {
  id: '55555555-5555-5555-5555-555555555555',
  slug: 'safety-checkup',
  name: 'Safety Checkup',
  description: 'Analyze URLs, messages, links, and text for scams, phishing, and malware threats.',
  icon: 'ShieldCheck',
  enabled: true,
  isSystem: true,
  archetype: 'deterministic_engine',
  visual: {
    themeAttribute: 'safety-checkup',
    accentColor: '#2563eb',
    iconName: 'ShieldCheck',
    avatarBg: '#10b981',
    avatarFg: '#ffffff',
    badgeText: 'Safety Checkup',
  },
  welcome: {
    heroTitle: 'Digital Safety Checkup',
    heroSubtitle: 'Analyze suspicious links, messages, emails, and scam requests.',
    heroIcon: 'ShieldCheck',
    suggestions: [
      { title: 'Check a suspicious URL', prompt: 'Is this URL safe or a phishing attempt? ', iconName: 'Link' },
      { title: 'Verify an unexpected text message', prompt: 'I received this text asking for urgent action. Is it a scam? ', iconName: 'MessageSquareWarning' },
      { title: 'Recovery phrase security inquiry', prompt: 'Someone claiming to be customer support asked for my wallet seed phrase. Should I share it?', iconName: 'Key' },
      { title: 'Analyze an invoice link', prompt: 'Check this payment notification link for deceptive signals: ', iconName: 'FileWarning' },
    ],
  },
  instructions: 'You are a protective digital safety assistant explaining online risks in plain, accessible language without technical jargon.',
  config: {
    instructions: 'You are a digital safety assistant. Review the provided deterministic safety analysis and explain the risk level, observable indicators, and actionable recommendations clearly to the user.',
  },
};

export const SECURITY_CHECKUP_THEME: ThemeDefinition = {
  id: '66666666-6666-6666-6666-666666666666',
  slug: 'security-checkup',
  name: 'Security Checkup',
  description: 'Technical inspection of suspicious links, headers, code, and threat indicators.',
  icon: 'ShieldAlert',
  enabled: true,
  isSystem: true,
  archetype: 'deterministic_engine',
  visual: {
    themeAttribute: 'security-checkup',
    accentColor: '#d97706',
    iconName: 'ShieldAlert',
    avatarBg: '#e11d48',
    avatarFg: '#ffffff',
    badgeText: 'Security Checkup',
  },
  welcome: {
    heroTitle: 'Technical Security Inspection',
    heroSubtitle: 'Audit web endpoints, security headers, token leaks, and vulnerabilities.',
    heroIcon: 'ShieldAlert',
    suggestions: [
      { title: 'Inspect URL structure and punycode', prompt: 'Perform a technical security breakdown on this suspicious domain: ', iconName: 'Terminal' },
      { title: 'Audit code for injection flaws', prompt: 'Inspect this server code for SQL injection or command injection risks: ', iconName: 'FileCode' },
      { title: 'Review HTTP security headers', prompt: 'Audit the recommended CSP and HSTS headers for this web service: ', iconName: 'ShieldCheck' },
      { title: 'Exposed credential audit', prompt: 'Check if this API URL inadvertently exposes sensitive credentials in query parameters:', iconName: 'AlertTriangle' },
    ],
  },
  instructions: 'You are a cybersecurity expert and threat analyst providing rigorous technical risk breakdowns, protocol analysis, and defensive engineering recommendations.',
  config: {
    instructions: 'You are a cybersecurity expert. Provide technical risk breakdowns and defensive recommendations based on observable threat signals.',
  },
};

export const STUDY_THEME: ThemeDefinition = {
  id: '44444444-4444-4444-4444-444444444444',
  slug: 'study',
  name: 'Study',
  description: 'Socratic tutor that helps you learn without giving away direct answers.',
  icon: 'BookOpen',
  enabled: true,
  isSystem: true,
  archetype: 'visual_prompt',
  visual: {
    themeAttribute: 'study',
    accentColor: '#7c3aed',
    iconName: 'BookOpen',
    avatarBg: '#7c3aed',
    avatarFg: '#ffffff',
    badgeText: 'Study',
  },
  welcome: {
    heroTitle: 'Socratic Learning Tutor',
    heroSubtitle: 'Deepen your understanding through guided questions, hints, and practice.',
    heroIcon: 'BookOpen',
    suggestions: [
      { title: 'Guide me through quantum mechanics', prompt: 'Guide me to understand wave-particle duality through questions:', iconName: 'Atom' },
      { title: 'Practice system design fundamentals', prompt: 'Help me practice designing a distributed rate limiter via Socratic dialogue:', iconName: 'Compass' },
      { title: 'World history analysis', prompt: 'Ask me questions to help me analyze the economic causes of the Industrial Revolution:', iconName: 'Globe' },
      { title: 'Language grammar breakdown', prompt: 'Test my understanding of Spanish subjunctive verb conjugations with exercises:', iconName: 'FileText' },
    ],
  },
  instructions: 'You are a Socratic tutor. Guide the student to the answer using questions and hints.',
  rules: ['Do not give the direct answer immediately', 'Ask probing questions'],
  config: {
    instructions: 'You are a Socratic tutor. Guide the student to the answer using questions and hints.',
    rules: ['Do not give the direct answer immediately', 'Ask probing questions'],
  },
};

/**
 * Dormant legacy theme definition (Tibb al-Nabi).
 * Preserved in code and registry for deterministic engine test compatibility,
 * but marked enabled: false and isSystem: false so it never appears in user menus.
 */
export const TIBB_AL_NABI_THEME: ThemeDefinition = {
  id: '77777777-7777-7777-7777-777777777777',
  slug: 'tibb-al-nabi',
  name: 'Tibb al-Nabi',
  description: 'Prophetic medicine and holistic traditional wellness principles.',
  icon: 'HeartPulse',
  enabled: false,
  isSystem: false,
  archetype: 'deterministic_engine',
  visual: {
    themeAttribute: 'tibb-al-nabi',
    accentColor: '#047857',
    iconName: 'HeartPulse',
    avatarBg: '#047857',
    avatarFg: '#ffffff',
    badgeText: 'Tibb al-Nabi',
  },
  welcome: {
    heroTitle: 'Tibb al-Nabi',
    heroSubtitle: 'Prophetic health principles.',
    heroIcon: 'HeartPulse',
    suggestions: [],
  },
  config: {},
};

/**
 * All active themes available to users.
 */
export const CANONICAL_THEMES: ThemeDefinition[] = [
  GENERAL_AI_THEME,
  MATHEMATICS_THEME,
  PROGRAMMING_THEME,
  SAFETY_CHECKUP_THEME,
  SECURITY_CHECKUP_THEME,
  STUDY_THEME,
];

/**
 * Fast lookup map by theme slug or database UUID (including legacy General AI UUID).
 */
export const CANONICAL_THEME_MAP: Record<string, ThemeDefinition> = {
  [GENERAL_AI_THEME.slug]: GENERAL_AI_THEME,
  [GENERAL_AI_THEME.id]: GENERAL_AI_THEME,
  [MATHEMATICS_THEME.slug]: MATHEMATICS_THEME,
  [MATHEMATICS_THEME.id]: MATHEMATICS_THEME,
  [PROGRAMMING_THEME.slug]: PROGRAMMING_THEME,
  [PROGRAMMING_THEME.id]: PROGRAMMING_THEME,
  [SAFETY_CHECKUP_THEME.slug]: SAFETY_CHECKUP_THEME,
  [SAFETY_CHECKUP_THEME.id]: SAFETY_CHECKUP_THEME,
  [SECURITY_CHECKUP_THEME.slug]: SECURITY_CHECKUP_THEME,
  [SECURITY_CHECKUP_THEME.id]: SECURITY_CHECKUP_THEME,
  [STUDY_THEME.slug]: STUDY_THEME,
  [STUDY_THEME.id]: STUDY_THEME,
  [TIBB_AL_NABI_THEME.slug]: TIBB_AL_NABI_THEME,
  [TIBB_AL_NABI_THEME.id]: TIBB_AL_NABI_THEME,
};
