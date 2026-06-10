# frozen_string_literal: true

module StrongerSecurityHelper
  # Returns an "Admin" badge for users with administrative privileges.
  # Covers both current admins and sudoers (redmine_sudo users who can grant
  # themselves admin rights at will). Returns nil for regular users.
  def stronger_admin_badge(user)
    return unless user
    return unless user.admin? || (user.respond_to?(:sudoer?) && user.sudoer?)

    content_tag(:span, l(:stronger_admin_badge), class: 'stronger-admin-badge')
  end

  def stronger_trusted_api_user_supported?
    User.column_names.include?('trusted_api_user')
  end
end
