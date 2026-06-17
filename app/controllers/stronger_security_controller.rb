# frozen_string_literal: true

class StrongerSecurityController < ApplicationController
  layout 'admin'
  self.main_menu = false
  before_action :require_admin

  def index
    metrics = RedmineStronger::SecurityMetrics

    # Simulate an unauthenticated visitor (Anonymous role)
    anon_scope           = Issue.visible(User.anonymous)
    @anon_total          = anon_scope.count
    @anon_open           = anon_scope.open.count
    @anon_top_projects   = @anon_total > 0 ? metrics.top_exposed_projects(anon_scope) : []

    # Simulate a logged-in user with no project memberships (Non-member role).
    # id=0 is intentional: user.id must be non-nil so that Issue.visible_condition
    # respects the role's issues_visibility setting ('own', 'default', 'all').
    # With id=nil the condition falls back to "all non-private issues", ignoring
    # per-project visibility rules entirely.
    ghost_user                = User.new(status: User::STATUS_ACTIVE)
    ghost_user.id             = 0
    non_member_scope          = Issue.visible(ghost_user)
    @non_member_total         = non_member_scope.count
    @non_member_open          = non_member_scope.open.count
    @non_member_top_projects  = @non_member_total > 0 ? metrics.top_exposed_projects(non_member_scope) : []

    threshold = metrics::LARGE_COUNT_THRESHOLD

    @inactive_users_count = metrics.inactive_users_count
    if @inactive_users_count <= threshold
      @inactive_users  = metrics.inactive_users
      @inactive_admins = []
    else
      # Too many to list individually: surface at least the inactive admins.
      @inactive_users  = []
      @inactive_admins = metrics.inactive_admins
    end

    @locked_users         = User.where(status: Principal::STATUS_LOCKED)
                                .where.not(lock_comment: nil)
                                .order(updated_on: :desc)

    api_users_scope       = metrics.api_users_scope
    @api_users_count      = api_users_scope.count
    @api_users_pages      = Redmine::Pagination::Paginator.new(
      @api_users_count, metrics::API_USERS_PER_PAGE, params[:page]
    )
    @api_users            = api_users_scope.limit(@api_users_pages.per_page)
                                           .offset(@api_users_pages.offset)
                                           .to_a
    @api_user_provenances = metrics.api_user_provenances(@api_users.map(&:user_id))
  end
end
