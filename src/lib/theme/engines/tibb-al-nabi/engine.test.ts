import { describe, it, expect } from 'vitest';
import { TibbAlNabiAnalyzer } from './analyzer';
import { TibbAlNabiEngine } from './engine';
import { TibbAlNabiContext } from './types';
import { Message } from '@/lib/ai/types';

describe('Tibb al-Nabi Theme Engine', () => {
  const analyzer = new TibbAlNabiAnalyzer();
  const engine = new TibbAlNabiEngine();

  const mockHistory: Message[] = [];

  const runPipeline = async (input: string, history: Message[] = mockHistory) => {
    const context = await analyzer.analyze(input, history);
    // Mimic processor mapping
    const fullContext = {
      themeId: 'mock-id',
      themeSlug: 'tibb-al-nabi',
      rawInput: input,
      history,
      facts: context.facts || {},
      entities: context.entities || [],
      conditions: context.conditions || [],
      intent: context.intent || null,
      metadata: context.metadata || {},
    };
    const result = await engine.execute(fullContext);
    return { context, result };
  };

  const getFacts = (context: unknown): TibbAlNabiContext['facts'] => (context as { facts: unknown }).facts as unknown as TibbAlNabiContext['facts'];

  it('A. Informational request - "What is Ṭibb al-Nabī?"', async () => {
    const { context, result } = await runPipeline('What is Tibb al-Nabi?');
    expect(context.intent).toBe('informational');
    expect(getFacts(context).medicalSafety).toBe('none');
    expect(result.explanationContext).toContain('Never fabricate a Hadith');
    expect(result.explanationContext).not.toContain('STRICT MEDICAL SAFETY MANDATE');
  });

  it('B. Hadith/source request - "What does the Hadith say about honey?"', async () => {
    const { context, result } = await runPipeline('What does the Hadith say about honey?');
    expect(context.intent).toBe('scholarly');
    expect(context.entities).toContain('honey');
    expect(getFacts(context).medicalSafety).toBe('none');
    expect(result.explanationContext).toContain('Never fabricate a Hadith');
    expect(result.explanationContext).toContain('entities were detected in the query: honey');
  });

  it('C. Diagnostic request - "I have a skin rash. What is it?"', async () => {
    const { context, result } = await runPipeline('I have a skin rash. What disease is it?');
    expect(getFacts(context).medicalSafety).toBe('diagnostic_request');
    expect(result.explanationContext).toContain('STRICT MEDICAL SAFETY MANDATE');
    expect(result.explanationContext).toContain('Do NOT diagnose the user');
  });

  it('D. Treatment request - "Which Prophetic remedy should I use for my ulcer?"', async () => {
    const { context, result } = await runPipeline('Which Prophetic remedy should I use to cure my ulcer?');
    expect(getFacts(context).medicalSafety).toBe('treatment_request');
    expect(result.explanationContext).toContain('STRICT MEDICAL SAFETY MANDATE');
  });

  it('E. Dosage request - "How much black seed should I take?"', async () => {
    const { context, result } = await runPipeline('How much black seed should I take?');
    expect(context.entities).toContain('black_seed');
    expect(getFacts(context).medicalSafety).toBe('dosage_request');
    expect(result.explanationContext).toContain('STRICT MEDICAL SAFETY MANDATE');
    expect(result.explanationContext).toContain('Do NOT prescribe a remedy or provide individualized dosage');
  });

  it('F. Medical image request', async () => {
    const history: Message[] = [{
      id: '1', role: 'user', content: 'data:image/png;base64,...', createdAt: new Date()
    }];
    const { context, result } = await runPipeline('What is this health issue?', history);
    expect(getFacts(context).medicalSafety).toBe('image_health_request');
    expect(result.explanationContext).toContain('STRICT MEDICAL SAFETY MANDATE');
  });

  it('G. Scientific question - "Is there scientific evidence for honey?"', async () => {
    const { context, result } = await runPipeline('Is there scientific evidence for honey?');
    expect(context.entities).toContain('honey');
    expect(result.explanationContext).toContain('Never fabricate');
    // It shouldn't block it as a diagnostic request.
    expect(getFacts(context).medicalSafety).toBe('none');
    expect(result.explanationContext).not.toContain('STRICT MEDICAL SAFETY MANDATE');
  });

  it('H. Challenge - "Ṭibb al-Nabī is outdated."', async () => {
    const { context, result } = await runPipeline('Tibb al-Nabi is outdated.');
    expect(context.intent).toBe('challenge');
    expect(getFacts(context).discussionMode).toBe('respectful_challenge');
    expect(result.explanationContext).toContain('ACADEMIC DISCUSSION MANDATE');
  });

  it('I. Unrelated question - "What is the capital of Japan?"', async () => {
    const { context, result } = await runPipeline('What is the capital of Japan?');
    expect(context.intent).toBe('unrelated');
    expect(result.explanationContext).toContain('UNRELATED QUERY');
    expect(result.explanationContext).not.toContain('Never fabricate a Hadith');
  });

  it('J. Multilingual inputs', async () => {
    const { context: arCtx } = await runPipeline('ما هو العسل؟');
    expect(getFacts(arCtx).language).toBe('arabic');

    const { context: mlCtx } = await runPipeline('തേൻ എന്താണ്?');
    expect(getFacts(mlCtx).language).toBe('malayalam');

    const { context: enCtx } = await runPipeline('What is honey?');
    expect(getFacts(enCtx).language).toBe('english');
  });

  it('K. Ensure no exact source is fabricated by the engine', async () => {
    const { result } = await runPipeline('Tell me a hadith about black seed.');
    expect(result.explanationContext).toContain('Never fabricate a Hadith');
    expect(result.explanationContext).toContain('If exact source text is not provided by the knowledge/retrieval layer in this context, do not fabricate');
  });

  it('L. Ensure informational religious questions are not incorrectly classified as medical prescriptions', async () => {
    const { context, result } = await runPipeline('What did Ibn al-Qayyim write about honey?');
    expect(context.intent).not.toBe('unrelated');
    expect(getFacts(context).medicalSafety).toBe('none');
    expect(result.explanationContext).not.toContain('STRICT MEDICAL SAFETY MANDATE');
  });
});
