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
    ghost_user                = metrics.non_member_user
    non_member_scope          = Issue.visible(ghost_user)
    @non_member_total         = non_member_scope.count
    @non_member_open          = non_member_scope.open.count
    @non_member_top_projects  = @non_member_total > 0 ? metrics.top_exposed_projects(non_member_scope) : []

    # Wiki and Documentation content readable without being a member.
    exposed_wikis                 = metrics.exposed_wikis(ghost_user)
    @exposed_wikis                = exposed_wikis[:wiki]
    @exposed_documentations       = exposed_wikis[:documentation]
    @wiki_projects_count          = metrics.module_enabled_projects_count(:wiki)
    @documentation_supported      = metrics.documentation_supported?
    @documentation_projects_count =
      @documentation_supported ? metrics.module_enabled_projects_count(:documentation) : 0

    threshold = metrics::LARGE_COUNT_THRESHOLD

    @inactive_users_count = metrics.inactive_users_count
    # Too many to list individually: only the inactive admins are listed.
    @inactive_users  = @inactive_users_count <= threshold ? metrics.inactive_users : []
    @inactive_admins = metrics.inactive_admins.to_a

    @locked_users         = User.where(status: Principal::STATUS_LOCKED)
                                .where.not(lock_comment: nil)
                                .order(updated_on: :desc)

    @api_blocked_attempts = metrics.api_blocked_attempts
    api_users_scope       = metrics.api_users_scope
    if @api_blocked_attempts.any?
      # Accounts with blocked attempts first, so that they never hide on a later page.
      blocked_ids = @api_blocked_attempts.keys.map(&:to_i).join(',')
      api_users_scope = api_users_scope.reorder(
        Arel.sql("CASE WHEN #{Token.table_name}.user_id IN (#{blocked_ids}) THEN 0 ELSE 1 END"), last_used_at: :desc
      )
    end
    @api_users_count      = api_users_scope.count
    @api_users_pages      = Redmine::Pagination::Paginator.new(
      @api_users_count, metrics::API_USERS_PER_PAGE, params[:page]
    )
    @api_users            = api_users_scope.limit(@api_users_pages.per_page)
                                           .offset(@api_users_pages.offset)
                                           .to_a
    @api_user_provenances = metrics.api_user_provenances(@api_users.map(&:user_id))
    @api_user_outcomes    = metrics.api_user_outcomes(@api_users.map(&:user_id))
  end

  def dependencies
    @report = StrongerDependencyReport.latest
    @running = StrongerDependencyReport.running
    failed = StrongerDependencyReport.failed_request
    @failed_request = failed if failed && (@report.nil? || failed.requested_at > @report.collected_at)
  end

  def collect_dependencies
    unless StrongerDependencyReport.running
      StrongerDependencyAuditJob.perform_later(StrongerDependencyReport.request!.id)
      flash[:notice] = l(:stronger_dependencies_collect_requested)
    end
    redirect_to stronger_security_dependencies_path
  end
end
