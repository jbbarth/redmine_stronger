# frozen_string_literal: true

module RedmineStronger
  module TokenPatch
    # Overrides Token.find_token to update last_used_at on API token usage.
    # Limit to one UPDATE per minute
    def find_token(action, key, validity_days = nil)
      token = super
      if token && action.to_s == 'api'
        if token.last_used_at.nil? || token.last_used_at < 1.minute.ago
          token.update_column(:last_used_at, Time.now)
        end
      end
      token
    end
  end
end

Token.singleton_class.prepend RedmineStronger::TokenPatch
