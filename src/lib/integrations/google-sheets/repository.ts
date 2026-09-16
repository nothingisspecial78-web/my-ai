import { createClient } from '@/lib/supabase/server';
import type { SupabaseClient } from '@supabase/supabase-js';
import type { Database } from '@/types/database';
import type { IntegrationStatus } from './types';

export interface StoredIntegration {
  id: string;
  user_id: string;
  status: IntegrationStatus;
  spreadsheet_id: string | null;
  spreadsheet_name: string | null;
  sheet_name: string;
  encrypted_refresh_token: string | null;
  token_iv: string | null;
  token_tag: string | null;
  last_synced_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export class GoogleSheetsRepository {
  public static async getIntegration(userId: string): Promise<StoredIntegration | null> {
    if (!userId) return null;
    try {
      const supabase = (await createClient()) as SupabaseClient<Database>;
      const { data, error } = await supabase
        .from('user_google_sheets_integrations')
        .select('*')
        .eq('user_id', userId)
        .maybeSingle();
      if (error || !data) return null;
      return data as unknown as StoredIntegration;
    } catch (e) {
      console.error('Error fetching Google Sheets integration:', e);
      return null;
    }
  }

  public static async saveIntegration(
    userId: string,
    params: {
      status?: IntegrationStatus;
      spreadsheet_id?: string | null;
      spreadsheet_name?: string | null;
      sheet_name?: string;
      encrypted_refresh_token?: string | null;
      token_iv?: string | null;
      token_tag?: string | null;
      last_synced_at?: string | null;
      last_error?: string | null;
    }
  ): Promise<StoredIntegration | null> {
    if (!userId) return null;
    try {
      const supabase = (await createClient()) as SupabaseClient<Database>;
      const existing = await this.getIntegration(userId);
      const payload = {
        ...params,
        updated_at: new Date().toISOString(),
      };
      if (existing) {
        const { data, error } = await supabase
          .from('user_google_sheets_integrations')
          .update(payload)
          .eq('user_id', userId)
          .select()
          .single();
        if (error) throw error;
        return data as unknown as StoredIntegration;
      } else {
        const { data, error } = await supabase
          .from('user_google_sheets_integrations')
          .insert({
            user_id: userId,
            status: params.status || 'disconnected',
            sheet_name: params.sheet_name || 'Security Telemetry',
            ...payload,
          })
          .select()
          .single();
        if (error) throw error;
        return data as unknown as StoredIntegration;
      }
    } catch (e) {
      console.error('Error saving Google Sheets integration:', e);
      return null;
    }
  }

  public static async updateStatus(
    userId: string,
    status: IntegrationStatus,
    lastError?: string | null
  ): Promise<boolean> {
    if (!userId) return false;
    try {
      const supabase = (await createClient()) as SupabaseClient<Database>;
      const { error } = await supabase
        .from('user_google_sheets_integrations')
        .update({
          status,
          last_error: lastError ?? null,
          updated_at: new Date().toISOString(),
        })
        .eq('user_id', userId);
      return !error;
    } catch {
      return false;
    }
  }

  public static async disconnect(userId: string): Promise<boolean> {
    if (!userId) return false;
    try {
      const supabase = (await createClient()) as SupabaseClient<Database>;
      const { error } = await supabase
        .from('user_google_sheets_integrations')
        .update({
          status: 'disconnected',
          encrypted_refresh_token: null,
          token_iv: null,
          token_tag: null,
          last_error: null,
          updated_at: new Date().toISOString(),
        })
        .eq('user_id', userId);
      return !error;
    } catch {
      return false;
    }
  }

  public static async isExported(userId: string, analysisId: string): Promise<boolean> {
    if (!userId || !analysisId) return false;
    try {
      const supabase = (await createClient()) as SupabaseClient<Database>;
      const { data } = await supabase
        .from('safety_analysis_exports')
        .select('id')
        .eq('user_id', userId)
        .eq('analysis_id', analysisId)
        .eq('destination', 'google_sheets')
        .maybeSingle();
      return !!data;
    } catch {
      return false;
    }
  }

  public static async recordExportSuccess(
    userId: string,
    analysisId: string,
    spreadsheetId: string,
    sheetName: string
  ): Promise<boolean> {
    if (!userId || !analysisId) return false;
    try {
      const supabase = (await createClient()) as SupabaseClient<Database>;
      const now = new Date().toISOString();
      await supabase
        .from('safety_analysis_exports')
        .insert({
          user_id: userId,
          analysis_id: analysisId,
          destination: 'google_sheets',
          spreadsheet_id: spreadsheetId,
          sheet_name: sheetName,
          status: 'exported',
          exported_at: now,
        });
      await supabase
        .from('user_google_sheets_integrations')
        .update({ last_synced_at: now, last_error: null, updated_at: now })
        .eq('user_id', userId);
      return true;
    } catch {
      return false;
    }
  }
}
