# frozen_string_literal: true

module RedmineStronger
  module UserPatch
    def self.prepended(base)
      base.has_many :login_sessions, class_name: 'UserLoginSession', dependent: :delete_all
    end
  end
end

User.prepend RedmineStronger::UserPatch
