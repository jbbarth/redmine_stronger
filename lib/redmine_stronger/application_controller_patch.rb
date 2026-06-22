# frozen_string_literal: true

module RedmineStronger
  module ApplicationControllerPatch

    def user_setup
      super
      track_api_key_session
    end

    # Rejects API-key requests that do not originate from the intranet zone,
    # when the restriction is enabled. Session-authenticated requests (no API
    # key) are never affected. Runs after user_setup, so the attempt is still
    # recorded on the security dashboard before being blocked.
    def enforce_intranet_only_api
      return unless stronger_block_internet_api?
      return unless stronger_api_key_request?
      return if RedmineStronger::Provenance.intranet?(request)

      render_403(message: :stronger_error_api_internet_blocked)
    end

    private

    def stronger_api_key_request?
      accept_api_auth? && Setting.rest_api_enabled? && api_key_from_request.present?
    end

    def stronger_block_internet_api?
      Setting['plugin_redmine_stronger']['block_internet_api'] == '1'
    rescue StandardError
      false
    end

    def track_api_key_session
      return unless stronger_api_key_request?

      key = api_key_from_request

      # When the account is locked the API authentication fails, so User.current
      # stays anonymous. We still resolve the owner from the token so the attempt
      # is recorded on the security dashboard.
      if User.current.is_a?(User) && User.current.logged?
        user    = User.current
        blocked = stronger_block_internet_api? &&
                  !RedmineStronger::Provenance.intranet?(request)
        outcome = blocked ? UserLoginSession::OUTCOME_BLOCKED : UserLoginSession::OUTCOME_SUCCESS
      else
        user    = Token.find_token('api', key)&.user
        outcome = UserLoginSession::OUTCOME_DENIED
      end
      return unless user

      record_api_key_session(user, outcome)
    end

    def record_api_key_session(user, outcome)
      ip = request.remote_ip
      last = UserLoginSession.where(user_id: user.id, auth_method: 'api_key',
                                    ip_address: ip, outcome: outcome)
                             .order(logged_in_at: :desc).first
      return if last && last.logged_in_at > 1.day.ago

      ua = request.user_agent.to_s
      UserLoginSession.create!(
        user:         user,
        logged_in_at: Time.now,
        ip_address:   ip,
        user_agent:   ua[0, 512],
        auth_method:  'api_key',
        outcome:      outcome,
        provenance:   RedmineStronger::Provenance.from_request(request),
        os:           UserLoginSession.parse_os(ua),
        device_type:  UserLoginSession.parse_device_type(ua)
      )

      keep_ids = UserLoginSession.where(user_id: user.id)
                                 .order(logged_in_at: :desc)
                                 .limit(UserLoginSession::MAX_SESSIONS_PER_USER)
                                 .pluck(:id)
      UserLoginSession.where(user_id: user.id).where.not(id: keep_ids).delete_all if keep_ids.any?
    end
  end
end

ApplicationController.prepend RedmineStronger::ApplicationControllerPatch

unless ApplicationController._process_action_callbacks.map(&:filter).include?(:enforce_intranet_only_api)
  ApplicationController.before_action :enforce_intranet_only_api
end
