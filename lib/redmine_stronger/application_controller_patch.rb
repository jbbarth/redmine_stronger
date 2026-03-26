# frozen_string_literal: true

module RedmineStronger
  module ApplicationControllerPatch

    def user_setup
      super
      track_api_key_session if api_key_auth_request?
    end

    private

    def api_key_auth_request?
      accept_api_auth? &&
        Setting.rest_api_enabled? &&
        api_key_from_request.present? &&
        User.current.is_a?(User) && User.current.logged?
    end

    def track_api_key_session
      user = User.current
      ip = request.remote_ip
      last = UserLoginSession.where(user_id: user.id, auth_method: 'api_key', ip_address: ip)
                             .order(logged_in_at: :desc).first
      return if last && last.logged_in_at > 1.day.ago

      ua = request.user_agent.to_s
      UserLoginSession.create!(
        user:         user,
        logged_in_at: Time.now,
        ip_address:   ip,
        user_agent:   ua[0, 512],
        auth_method:  'api_key',
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
