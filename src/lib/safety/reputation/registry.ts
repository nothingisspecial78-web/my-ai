/**
 * Reputation Provider Registry
 * 
 * Manages the registration, lifecycle, and retrieval of URL reputation providers.
 */

import { ReputationProvider } from './types';

export class ReputationProviderRegistry {
  private providers = new Map<string, ReputationProvider>();

  /**
   * Registers a reputation provider.
   */
  register(provider: ReputationProvider): void {
    this.providers.set(provider.id, provider);
  }

  /**
   * Unregisters a provider by its identifier.
   */
  unregister(id: string): void {
    this.providers.delete(id);
  }

  /**
   * Retrieves a specific provider by ID.
   */
  get(id: string): ReputationProvider | undefined {
    return this.providers.get(id);
  }

  /**
   * Returns all registered providers.
   */
  getAll(): ReputationProvider[] {
    return Array.from(this.providers.values());
  }

  /**
   * Returns all active providers (status not 'disabled' and not 'unavailable').
   */
  getActive(): ReputationProvider[] {
    return this.getAll().filter(p => {
      const status = p.getStatus();
      return status !== 'disabled' && status !== 'unavailable';
    });
  }

  /**
   * Clears all registered providers (primarily for test cleanup).
   */
  clear(): void {
    this.providers.clear();
  }
}

// Global default singleton registry
export const reputationRegistry = new ReputationProviderRegistry();
