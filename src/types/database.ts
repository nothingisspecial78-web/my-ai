export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export interface Database {
  public: {
    Tables: {
      themes: {
        Row: {
          id: string
          name: string
          slug: string
          description: string | null
          icon: string | null
          enabled: boolean
          is_system: boolean
          config: Json
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          name: string
          slug: string
          description?: string | null
          icon?: string | null
          enabled?: boolean
          is_system?: boolean
          config?: Json
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          name?: string
          slug?: string
          description?: string | null
          icon?: string | null
          enabled?: boolean
          is_system?: boolean
          config?: Json
          created_at?: string
          updated_at?: string
        }
        Relationships: []
      }
      profiles: {
        Row: {
          id: string
          email: string
          full_name: string | null
          avatar_url: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id: string
          email: string
          full_name?: string | null
          avatar_url?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          email?: string
          full_name?: string | null
          avatar_url?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: []
      }
      conversations: {
        Row: {
          id: string
          user_id: string
          title: string
          theme_id: string | null
          created_at: string
          updated_at: string
          deleted_at: string | null
        }
        Insert: {
          id?: string
          user_id: string
          title: string
          theme_id?: string | null
          created_at?: string
          updated_at?: string
          deleted_at?: string | null
        }
        Update: {
          id?: string
          user_id?: string
          title?: string
          theme_id?: string | null
          created_at?: string
          updated_at?: string
          deleted_at?: string | null
        }
        Relationships: []
      }
      messages: {
        Row: {
          id: string
          conversation_id: string
          user_id: string
          role: 'user' | 'assistant' | 'system'
          content: string
          model: string | null
          provider: string | null
          input_tokens: number | null
          output_tokens: number | null
          metadata: Json | null
          created_at: string
        }
        Insert: {
          id?: string
          conversation_id: string
          user_id: string
          role: 'user' | 'assistant' | 'system'
          content: string
          model?: string | null
          provider?: string | null
          input_tokens?: number | null
          output_tokens?: number | null
          metadata?: Json | null
          created_at?: string
        }
        Update: {
          id?: string
          conversation_id?: string
          user_id?: string
          role?: 'user' | 'assistant' | 'system'
          content?: string
          model?: string | null
          provider?: string | null
          input_tokens?: number | null
          output_tokens?: number | null
          metadata?: Json | null
          created_at?: string
        }
        Relationships: []
      }
      safety_analyses: {
        Row: {
          id: string
          conversation_id: string | null
          message_id: string | null
          user_id: string
          input_type: string
          risk_level: string
          confidence_level: string
          score: number | null
          summary: string
          created_at: string
        }
        Insert: {
          id?: string
          conversation_id?: string | null
          message_id?: string | null
          user_id: string
          input_type: string
          risk_level: string
          confidence_level: string
          score?: number | null
          summary: string
          created_at?: string
        }
        Update: {
          id?: string
          conversation_id?: string | null
          message_id?: string | null
          user_id?: string
          input_type?: string
          risk_level?: string
          confidence_level?: string
          score?: number | null
          summary?: string
          created_at?: string
        }
        Relationships: []
      }
      safety_findings: {
        Row: {
          id: string
          analysis_id: string
          type: string
          title: string
          description: string
          severity: string
          confidence: string
          created_at: string
        }
        Insert: {
          id?: string
          analysis_id: string
          type: string
          title: string
          description: string
          severity: string
          confidence: string
          created_at?: string
        }
        Update: {
          id?: string
          analysis_id?: string
          type?: string
          title?: string
          description?: string
          severity?: string
          confidence?: string
          created_at?: string
        }
        Relationships: []
      }
      safety_evidence: {
        Row: {
          id: string
          analysis_id: string
          finding_id: string | null
          evidence_type: string
          label: string
          snippet: string | null
          data: Json | null
          created_at: string
        }
        Insert: {
          id?: string
          analysis_id: string
          finding_id?: string | null
          evidence_type: string
          label: string
          snippet?: string | null
          data?: Json | null
          created_at?: string
        }
        Update: {
          id?: string
          analysis_id?: string
          finding_id?: string | null
          evidence_type?: string
          label?: string
          snippet?: string | null
          data?: Json | null
          created_at?: string
        }
        Relationships: []
      }
      safety_recommendations: {
        Row: {
          id: string
          analysis_id: string
          action: string
          title: string
          description: string
          priority: string
          created_at: string
        }
        Insert: {
          id?: string
          analysis_id: string
          action: string
          title: string
          description: string
          priority: string
          created_at?: string
        }
        Update: {
          id?: string
          analysis_id?: string
          action?: string
          title?: string
          description?: string
          priority?: string
          created_at?: string
        }
        Relationships: []
      }
      user_google_sheets_integrations: {
        Row: {
          id: string
          user_id: string
          status: 'connected' | 'disconnected' | 'revoked' | 'error'
          spreadsheet_id: string | null
          spreadsheet_name: string | null
          sheet_name: string
          encrypted_refresh_token: string | null
          token_iv: string | null
          token_tag: string | null
          last_synced_at: string | null
          last_error: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          user_id: string
          status?: 'connected' | 'disconnected' | 'revoked' | 'error'
          spreadsheet_id?: string | null
          spreadsheet_name?: string | null
          sheet_name?: string
          encrypted_refresh_token?: string | null
          token_iv?: string | null
          token_tag?: string | null
          last_synced_at?: string | null
          last_error?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          user_id?: string
          status?: 'connected' | 'disconnected' | 'revoked' | 'error'
          spreadsheet_id?: string | null
          spreadsheet_name?: string | null
          sheet_name?: string
          encrypted_refresh_token?: string | null
          token_iv?: string | null
          token_tag?: string | null
          last_synced_at?: string | null
          last_error?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: []
      }
      safety_analysis_exports: {
        Row: {
          id: string
          user_id: string
          analysis_id: string
          destination: string
          spreadsheet_id: string
          sheet_name: string
          status: string
          exported_at: string
        }
        Insert: {
          id?: string
          user_id: string
          analysis_id: string
          destination?: string
          spreadsheet_id: string
          sheet_name: string
          status?: string
          exported_at?: string
        }
        Update: {
          id?: string
          user_id?: string
          analysis_id?: string
          destination?: string
          spreadsheet_id?: string
          sheet_name?: string
          status?: string
          exported_at?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      message_role: 'user' | 'assistant' | 'system'
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}
