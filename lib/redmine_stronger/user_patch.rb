# frozen_string_literal: true

require_relative "brute_force"

module RedmineStronger
  module UserPatch
    def self.prepended(base)
      base.has_many :login_sessions, class_name: 'UserLoginSession', dependent: :delete_all
      base.singleton_class.prepend(ClassMethods)
    end

    # Extend brute-force protection to API HTTP Basic authentication.
    module ClassMethods
      def try_to_login(login, password, active_only = true)
        RedmineStronger::BruteForce.unlock_if_expired(login)
        user = super
        if user
          RedmineStronger::BruteForce.reset(user)
        else
          RedmineStronger::BruteForce.register_failure(login)
        end
        user
      end
    end
  end
end

User.prepend RedmineStronger::UserPatch
