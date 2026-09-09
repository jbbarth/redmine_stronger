# frozen_string_literal: true

module RedmineStronger
  module SecurityMetrics
    INACTIVE_DAYS        = 360
    TOP_PROJECTS_LIMIT   = 10
    INACTIVE_USERS_LIMIT = 15
    API_USERS_PER_PAGE   = 25

    WIKI_PERMISSION          = :view_wiki_pages
    DOCUMENTATION_PERMISSION = :view_documentation_pages

    # Above this threshold, individual user lists are not shown (count only).
    LARGE_COUNT_THRESHOLD = 50

    ExposedWiki = Struct.new(:project, :pages, :attachments)

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
    def self.api_users_scope
      Token.where(action: 'api')
           .where.not(last_used_at: nil)
           .includes(:user)
           .order(last_used_at: :desc)
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

    # Maps user_id => outcome of the most recent API key attempt.
    def self.api_user_outcomes(user_ids)
      return {} if user_ids.blank?
      UserLoginSession.where(user_id: user_ids, auth_method: 'api_key')
                      .order(logged_in_at: :desc)
                      .pluck(:user_id, :outcome)
                      .each_with_object({}) { |(uid, out), h| h[uid] ||= out }
    end

    # A logged-in user with no project membership: what the builtin "Non member"
    # role exposes on public projects.
    #
    # id=0 is intentional: user.id must be non-nil so that permission conditions
    # respect the role settings ('own', 'default', 'all') and exclude projects
    # where the builtin Non member group holds custom roles. With id=nil the
    # conditions fall back to a permissive default, ignoring those rules.
    def self.non_member_user
      user = User.new(status: User::STATUS_ACTIVE)
      user.id = 0
      user
    end

    # True when the redmine_second_wiki plugin provides the Documentation tab.
    def self.documentation_supported?
      Redmine::AccessControl.permission(DOCUMENTATION_PERMISSION).present? &&
        Wiki.column_names.include?('documentation_start_page')
    end

    # Number of non-archived projects with the given module enabled, i.e. the
    # projects for which the exposure question makes sense.
    def self.module_enabled_projects_count(name)
      Project.where(status: [Project::STATUS_ACTIVE, Project::STATUS_CLOSED])
             .has_module(name)
             .count
    end

    # Projects whose wiki (and Documentation tab) the given user can read
    # without being a member of them.
    #
    # Returns {wiki: [ExposedWiki, ...], documentation: [ExposedWiki, ...]},
    # each list ordered by the amount of content it discloses. The two lists
    # partition the pages of a project: a page belongs to the Documentation
    # side when it descends from the documentation start page, as decided by
    # WikiPage#documentation_page? in redmine_second_wiki.
    def self.exposed_wikis(user)
      wiki_project_ids = Project.allowed_to(user, WIKI_PERMISSION).ids
      doc_project_ids =
        documentation_supported? ? Project.allowed_to(user, DOCUMENTATION_PERMISSION).ids : []

      project_ids = wiki_project_ids | doc_project_ids
      projects = Project.where(id: project_ids).index_by(&:id)
      counts = wiki_content_counts(project_ids)

      {
        wiki: exposure_rows(wiki_project_ids, projects, counts, :wiki),
        documentation: exposure_rows(doc_project_ids, projects, counts, :documentation)
      }
    end

    def self.exposure_rows(project_ids, projects, counts, side)
      project_ids.filter_map do |project_id|
        project = projects[project_id]
        next unless project

        pages, attachments = counts[project_id][side]
        ExposedWiki.new(project, pages, attachments)
      end.sort_by {|row| [-row.pages, -row.attachments, row.project.name.to_s.downcase]}
    end
    private_class_method :exposure_rows

    # Maps project_id => {wiki: [pages, attachments], documentation: [pages, attachments]}.
    def self.wiki_content_counts(project_ids)
      counts = Hash.new {|h, k| h[k] = {wiki: [0, 0], documentation: [0, 0]}}
      return counts if project_ids.blank?

      wikis = Wiki.where(project_id: project_ids).to_a
      return counts if wikis.empty?

      pages_by_wiki =
        WikiPage.where(wiki_id: wikis.map(&:id))
                .pluck(:id, :wiki_id, :parent_id, :title)
                .group_by {|_id, wiki_id, _parent_id, _title| wiki_id}
      attachments_by_page = wiki_attachment_counts(wikis.map(&:id))

      wikis.each do |wiki|
        pages = pages_by_wiki[wiki.id] || []
        documentation_ids = documentation_page_ids(wiki, pages)

        total_attachments = pages.sum {|id, _w, _p, _t| attachments_by_page[id].to_i}
        documentation_attachments =
          documentation_ids.sum {|id| attachments_by_page[id].to_i}

        counts[wiki.project_id] = {
          wiki: [pages.size - documentation_ids.size,
                 total_attachments - documentation_attachments],
          documentation: [documentation_ids.size, documentation_attachments]
        }
      end

      counts
    end

    # Maps wiki page id => number of attachments, for the given wikis.
    def self.wiki_attachment_counts(wiki_ids)
      Attachment.where(container_type: 'WikiPage')
                .joins("INNER JOIN #{WikiPage.table_name} wp ON wp.id = #{Attachment.table_name}.container_id")
                .where(wp: {wiki_id: wiki_ids})
                .group('wp.id')
                .count
    end
    private_class_method :wiki_attachment_counts

    # Ids of the pages served under the Documentation tab: the subtree rooted at
    # the documentation start page. Pages rooted anywhere else, orphans included,
    # belong to the regular wiki.
    def self.documentation_page_ids(wiki, pages)
      return Set.new unless documentation_supported?

      start_page = wiki.documentation_start_page
      return Set.new if start_page.blank?

      root = pages.detect {|_id, _wiki_id, _parent_id, title| title.to_s.tr('_', ' ') == start_page}
      return Set.new unless root

      children = Hash.new {|h, k| h[k] = []}
      titles = {}
      pages.each do |id, _wiki_id, parent_id, title|
        children[parent_id] << id if parent_id
        titles[id] = title.to_s.tr('_', ' ')
      end

      subtree = Set.new
      queue = [root[0]]
      until queue.empty?
        id = queue.shift
        # A wiki start page nested under the documentation root roots its own
        # subtree back into the wiki, per WikiPage#root_page.
        next if id != root[0] && titles[id] == wiki.start_page
        next unless subtree.add?(id)

        queue.concat(children[id])
      end
      subtree
    end
    private_class_method :documentation_page_ids
  end
end
