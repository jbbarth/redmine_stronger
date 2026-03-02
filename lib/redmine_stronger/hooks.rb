# frozen_string_literal: true

module RedmineStronger
  class Hooks < Redmine::Hook::ViewListener
    # Records a login session after each successful authentication.
    # Works for both password-based and CAS/OmniAuth logins.
    #
    # Note: session[:logged_in_with_cas] cannot be used here because it is set
    # *after* successful_authentication() (which calls reset_session). Instead,
    # request.env["omniauth.auth"] is present throughout the whole CAS request.
    def controller_account_success_authentication_after(context = {})
      user = context[:user]
      req  = context[:request]
      return unless user.is_a?(User) && req

      auth_method = detect_auth_method(req, user)
      ua = req.user_agent.to_s

      UserLoginSession.create!(
        user:        user,
        logged_in_at: Time.now,
        ip_address:  req.remote_ip,
        user_agent:  ua[0, 512],
        auth_method: auth_method,
        os:          UserLoginSession.parse_os(ua),
        device_type: UserLoginSession.parse_device_type(ua)
      )

      cleanup_old_sessions(user)
    end

    # Renders the login sessions list on the user profile page (admin only).
    def view_account_left_bottom(context = {})
      return unless User.current.admin?

      user     = context[:user]
      sessions = UserLoginSession.for_display(user)
      context[:controller].send(:render_to_string,
        partial: 'redmine_stronger/login_sessions/list',
        locals:  { sessions: sessions, show_title: true })
    end

    private

    def detect_auth_method(req, user)
      if req.env["omniauth.auth"].present?
        req.env["omniauth.auth"]["provider"].presence || "sso"
      elsif user.auth_source_id.present?
        "ldap"
      else
        "password"
      end
    end

    def cleanup_old_sessions(user)
      keep_ids = UserLoginSession.where(user_id: user.id)
                                 .order(logged_in_at: :desc)
                                 .limit(UserLoginSession::MAX_SESSIONS_PER_USER)
                                 .pluck(:id)
      UserLoginSession.where(user_id: user.id).where.not(id: keep_ids).delete_all if keep_ids.any?
    end
  end
end
