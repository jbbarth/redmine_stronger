# frozen_string_literal: true

module RedmineStronger
  module SecurityMetrics
    INACTIVE_DAYS        = 360
    TOP_PROJECTS_LIMIT   = 10
    INACTIVE_USERS_LIMIT = 15
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
    def self.inactive_users
      User.active
          .where("last_login_on IS NULL OR last_login_on < ?", INACTIVE_DAYS.days.ago)
          .order(Arel.sql("last_login_on ASC NULLS FIRST"))
          .limit(INACTIVE_USERS_LIMIT)
    end

    # Count of active users who haven't logged in for INACTIVE_DAYS days (or never).
    def self.inactive_users_count
      User.active
          .where("last_login_on IS NULL OR last_login_on < ?", INACTIVE_DAYS.days.ago)
          .count
    end

    # Active users without 2FA enabled. Only meaningful if Setting.twofa? is true.
    def self.users_without_2fa
      User.active.where(twofa_scheme: nil)
    end
  end
end
