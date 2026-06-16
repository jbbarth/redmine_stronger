# frozen_string_literal: true

module RedmineStronger
  module SecurityMetrics
    INACTIVE_DAYS        = 360
    TOP_PROJECTS_LIMIT   = 10
    INACTIVE_USERS_LIMIT = 15
    API_USERS_LIMIT      = 25
    # Above this threshold, individual user lists are not shown (count only).
    LARGE_COUNT_THRESHOLD = 50

    # Returns the top exposed projects, with open and total issue counts.
    # Expects an Issue scope (e.g. Issue.visible(User.anonymous)).
    def self.top_exposed_projects(base_scope)
      open_status_ids = IssueStatus.where(is_closed: false).pluck(:id)
      open_count_sql  = open_status_ids.any? ?
        "SUM(CASE WHEN #{Issue.table_name}.status_id IN (#{open_status_ids.join(',')}) THEN 1 ELSE 0 END)" :
        "0"

      base_scope
        .joins(:project)
        .group("#{Project.table_name}.id", "#{Project.table_name}.name", "#{Project.table_name}.identifier")
        .select(
          "#{Project.table_name}.id",
          "#{Project.table_name}.name",
          "#{Project.table_name}.identifier",
          "COUNT(#{Issue.table_name}.id) AS total_count",
          "#{open_count_sql} AS open_count"
        )
        .order("total_count DESC")
        .limit(TOP_PROJECTS_LIMIT)
    end

    # Active users who haven't logged in for INACTIVE_DAYS days (or never).
    # API usage counts as activity: last_login_on is not updated on API key
    # authentication, so users whose API token was used recently are excluded.
    def self.inactive_users_scope
      cutoff = INACTIVE_DAYS.days.ago
      recent_api_user_ids = Token.where(action: 'api')
                                 .where('last_used_at >= ?', cutoff)
                                 .select(:user_id)
      User.active
          .where("last_login_on IS NULL OR last_login_on < ?", cutoff)
          .where.not(id: recent_api_user_ids)
          .order(Arel.sql("last_login_on ASC NULLS FIRST"))
    end

    def self.inactive_users
      inactive_users_scope.limit(INACTIVE_USERS_LIMIT)
    end

    # Count of active users who haven't logged in for INACTIVE_DAYS days (or never).
    def self.inactive_users_count
      inactive_users_scope.count
    end

    # Inactive users with administrative privileges (admins and, when the
    # redmine_sudo plugin is installed, sudoers). Shown even when the full
    # inactive list is too large to display, since stale admin accounts are
    # the highest-risk subset.
    def self.inactive_admins
      scope = inactive_users_scope
      if User.column_names.include?('sudoer')
        scope.where("admin = ? OR sudoer = ?", true, true)
      else
        scope.where(admin: true)
      end
    end

    # API tokens that have been used to authenticate, most recently used first.
    def self.api_users
      Token.where(action: 'api')
           .where.not(last_used_at: nil)
           .includes(:user)
           .order(last_used_at: :desc)
           .limit(API_USERS_LIMIT)
    end

    # Maps user_id => most recent provenance recorded on an API key session.
    def self.api_user_provenances(user_ids)
      return {} if user_ids.blank?
      UserLoginSession.where(user_id: user_ids, auth_method: 'api_key')
                      .where.not(provenance: nil)
                      .order(logged_in_at: :desc)
                      .pluck(:user_id, :provenance)
                      .each_with_object({}) { |(uid, prov), h| h[uid] ||= prov }
    end
  end
end
