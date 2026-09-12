/**
 * Deterministic Entity Matcher (Phase 6.2)
 * 
 * Identifies claimed institutions, banks, tech platforms, couriers, and government
 * agencies mentioned in message text. Factual and grounded: never claims maliciousness
 * of the organization itself.
 */

import { ClaimedEntity, ClaimedEntityCategory } from './types';

interface EntityDefinition {
  name: string;
  category: ClaimedEntityCategory;
  patterns: RegExp[];
}

export class EntityMatcher {
  private static ENTITY_CATALOG: EntityDefinition[] = [
    // Banking & Payment Services
    {
      name: 'State Bank of India',
      category: 'banking',
      patterns: [/\b(?:sbi|state bank of india|yono sbi)\b/i],
    },
    {
      name: 'HDFC Bank',
      category: 'banking',
      patterns: [/\bhdfc(?: bank)?\b/i],
    },
    {
      name: 'ICICI Bank',
      category: 'banking',
      patterns: [/\bicici(?: bank)?\b/i],
    },
    {
      name: 'Axis Bank',
      category: 'banking',
      patterns: [/\baxis bank\b/i],
    },
    {
      name: 'Punjab National Bank (PNB)',
      category: 'banking',
      patterns: [/\b(?:pnb|punjab national bank)\b/i],
    },
    {
      name: 'Bank of Baroda',
      category: 'banking',
      patterns: [/\bbank of baroda\b/i],
    },
    {
      name: 'PayPal',
      category: 'banking',
      patterns: [/\bpaypa[l1]\b/i],
    },
    {
      name: 'Paytm',
      category: 'banking',
      patterns: [/\bpaytm\b/i],
    },
    {
      name: 'PhonePe',
      category: 'banking',
      patterns: [/\bphonepe\b/i],
    },
    {
      name: 'Google Pay',
      category: 'banking',
      patterns: [/\b(?:google pay|gpay)\b/i],
    },
    {
      name: 'Chase Bank',
      category: 'banking',
      patterns: [/\b(?:chase bank|jpmorgan chase)\b/i],
    },
    {
      name: 'Wells Fargo',
      category: 'banking',
      patterns: [/\bwells fargo\b/i],
    },
    {
      name: 'Bank of America',
      category: 'banking',
      patterns: [/\b(?:bank of america|bofa)\b/i],
    },

    // Couriers & Delivery Services
    {
      name: 'India Post',
      category: 'courier',
      patterns: [/\b(?:india post|post office parcel|speed post)\b/i],
    },
    {
      name: 'FedEx',
      category: 'courier',
      patterns: [/\bfedex\b/i],
    },
    {
      name: 'DHL',
      category: 'courier',
      patterns: [/\bdhl\b/i],
    },
    {
      name: 'UPS',
      category: 'courier',
      patterns: [/\bups (?:delivery|parcel|courier|shipment)\b/i],
    },
    {
      name: 'USPS',
      category: 'courier',
      patterns: [/\busps\b/i],
    },
    {
      name: 'Blue Dart',
      category: 'courier',
      patterns: [/\bblue dart\b/i],
    },

    // Tech Platforms & Services
    {
      name: 'Google',
      category: 'technology',
      patterns: [/\bgoogle (?:support|security|team|account)\b/i],
    },
    {
      name: 'Apple',
      category: 'technology',
      patterns: [/\bapple (?:support|id|security|icloud)\b/i],
    },
    {
      name: 'Microsoft',
      category: 'technology',
      patterns: [/\bmicrosoft (?:support|security|365|windows support)\b/i],
    },
    {
      name: 'Amazon',
      category: 'technology',
      patterns: [/\bamazon (?:customer service|support|order|delivery|refund)\b/i],
    },
    {
      name: 'Netflix',
      category: 'technology',
      patterns: [/\bnetflix\b/i],
    },
    {
      name: 'WhatsApp',
      category: 'platform',
      patterns: [/\bwhatsapp\b/i],
    },
    {
      name: 'Telegram',
      category: 'platform',
      patterns: [/\btelegram\b/i],
    },

    // Government & Official Enforcement
    {
      name: 'Income Tax Department',
      category: 'government',
      patterns: [/\b(?:income tax department|it department|income tax refund)\b/i],
    },
    {
      name: 'Internal Revenue Service (IRS)',
      category: 'government',
      patterns: [/\b(?:irs|internal revenue service)\b/i],
    },
    {
      name: 'Customs & Border Protection',
      category: 'government',
      patterns: [/\b(?:customs department|customs clearance|customs duty|parcel held at customs)\b/i],
    },
    {
      name: 'Law Enforcement / Police',
      category: 'government',
      patterns: [/\b(?:police department|cyber cell|cyber crime|cbi|enforcement directorate|court summons|arrest warrant)\b/i],
    },

    // Corporate HR / Employment
    {
      name: 'Corporate HR / Recruitment',
      category: 'corporate_hr',
      patterns: [/\b(?:hr team|hr department|recruitment team|talent acquisition|hiring manager)\b/i],
    },
  ];

  /**
   * Matches all claimed entities in the text with exact phrase grounding.
   */
  static matchEntities(text: string): ClaimedEntity[] {
    if (!text) return [];
    const matched: ClaimedEntity[] = [];
    const seenNames = new Set<string>();

    for (const def of this.ENTITY_CATALOG) {
      for (const pattern of def.patterns) {
        const match = pattern.exec(text);
        if (match && !seenNames.has(def.name)) {
          seenNames.add(def.name);
          matched.push({
            name: def.name,
            category: def.category,
            matchedText: match[0],
            description: `The communication claims affiliation or association with ${def.name}.`,
          });
          break; // Avoid adding the same entity multiple times
        }
      }
    }

    return matched;
  }
}
