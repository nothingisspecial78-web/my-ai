/**
 * Reputation Intelligence Architecture Types
 * 
 * Defines provider contracts, normalized reputation findings, evidence models,
 * aggregator structures, and caching interfaces for Live URL Reputation Intelligence.
 */

import { ConfidenceLevel, Evidence, Finding } from '../types';

// Normalized detection states across all reputation providers
export type ReputationDetectionStatus =
  | 'malicious'
  | 'suspicious'
  | 'clean'
  | 'unknown'
  | 'unavailable';

// Operational status of an individual provider
export type ProviderStatus =
  | 'ready'
  | 'degraded'
  | 'rate_limited'
  | 'disabled'
  | 'unavailable';

// Standard threat classification categories reported by providers
export type ReputationThreatCategory =
  | 'malware'
  | 'phishing'
  | 'scam'
  | 'unwanted'
  | 'cryptominer'
  | 'botnet'
  | 'command_and_control'
  | 'suspicious'
  | 'unknown';

// Standardized provider error container
export interface ReputationError {
  code:
    | 'timeout'
    | 'rate_limited'
    | 'network_error'
    | 'invalid_response'
    | 'provider_unavailable'
    | 'unknown';
  message: string;
  statusCode?: number;
  retryAfterMs?: number;
}

// Normalized output returned by a single reputation provider
export interface ProviderReputationResult {
  providerId: string;
  providerName: string;
  url: string; // Normalized and privacy-redacted URL string
  status: ProviderStatus;
  detectionStatus: ReputationDetectionStatus;
  confidence: ConfidenceLevel;
  threatCategories?: ReputationThreatCategory[];
  rawDetails?: Record<string, unknown>;
  evidence: Evidence;
  timestamp: string; // ISO 8601 string
  latencyMs: number;
  cached: boolean;
  error?: ReputationError;
}

// Runtime lookup options passed into provider requests
export interface ReputationLookupOptions {
  timeoutMs?: number;
  bypassCache?: boolean;
  signal?: AbortSignal;
}

// Core reputation provider contract
export interface ReputationProvider {
  readonly id: string;
  readonly name: string;
  readonly defaultTimeoutMs: number;
  getStatus(): ProviderStatus;
  lookupUrl(url: string, options?: ReputationLookupOptions): Promise<ProviderReputationResult>;
}

// Result of aggregating multiple reputation providers
export interface AggregatedReputationResult {
  url: string; // Normalized & redacted
  aggregateStatus: ReputationDetectionStatus;
  confidence: ConfidenceLevel;
  consensusScore: number; // Score from -1.0 (clean) to +1.0 (malicious)
  disputed: boolean;
  providerResults: ProviderReputationResult[];
  findings: Finding[];
  evidence: Evidence[];
  limitations: string[];
  summary: string;
}

// Cached representation of a provider lookup
export interface ReputationCacheEntry {
  result: ProviderReputationResult;
  cachedAt: number; // Epoch timestamp ms
  expiresAt: number; // Epoch timestamp ms
  stale: boolean;
}

// Provider-agnostic cache storage contract
export interface ReputationCache {
  get(key: string): Promise<ReputationCacheEntry | null>;
  set(key: string, entry: ReputationCacheEntry, ttlSeconds?: number): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
}
