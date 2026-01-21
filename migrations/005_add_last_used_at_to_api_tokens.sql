-- Add last_used_at column to api_tokens table
ALTER TABLE api_tokens ADD COLUMN last_used_at TIMESTAMP WITH TIME ZONE;

-- Create index for last_used_at for performance
CREATE INDEX idx_api_tokens_last_used_at ON api_tokens(last_used_at);