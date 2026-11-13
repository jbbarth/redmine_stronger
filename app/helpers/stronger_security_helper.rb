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

  # Badge for users approved for the API (trusted_api_user, from redmine_scn).
  def stronger_trusted_api_badge(user)
    return unless user.respond_to?(:trusted_api_user?) && user.trusted_api_user?

    content_tag(:span, l(:stronger_trusted_api_badge), class: 'stronger-trusted-badge')
  end

  # Blocked attempts stand out, then use from internet.
  def stronger_api_row_status(blocked, provenance)
    if blocked > 0
      'vulnerable'
    elsif RedmineStronger::Provenance.classify(provenance) == :internet
      'outdated'
    else
      'none'
    end
  end

  def stronger_security_tabs(selected)
    render_tabs([
                  { name: 'overview', label: :stronger_tab_overview, url: stronger_security_path },
                  { name: 'dependencies', label: :stronger_tab_dependencies, url: stronger_security_dependencies_path }
                ], selected)
  end

  def stronger_severity_badge(level)
    content_tag(:span, l("stronger_severity_#{level}"), class: "stronger-severity stronger-severity-#{level}")
  end

  # Support status of a release cycle (endoflife.date).
  def stronger_support_badge(item)
    status, date =
      if item['eol']
        ['eol', item['eol_date']]
      elsif item['security_only']
        ['security_only', item['eol_date']]
      elsif item['cycle_unknown']
        ['unknown', nil]
      elsif item['cycle']
        ['supported', item['eol_date']]
      end
    return unless status

    badge = content_tag(:span, l("stronger_support_#{status}"), class: "stronger-support stronger-support-#{status}")
    date ? safe_join([badge, content_tag(:span, l(:stronger_support_until, date: format_date(date.to_date)), class: 'stronger-muted')], ' ') : badge
  end

  # A newer version, shown only when it differs from the installed one.
  def stronger_newer_version(item, key)
    newer = item[key]
    return if newer.blank? || newer == item['version']

    content_tag(:span, newer, class: 'stronger-newer')
  end

  # Colour status of an audited item, most severe first:
  # alert (critical or high vulnerability, end of life), vulnerable,
  # outdated (newer release in its branch, apt update, plugin behind),
  # ok, unknown (nothing could be checked).
  def stronger_item_status(item)
    advisories = item['advisories']
    severity = RedmineStronger::DependencyAudit::Severity
    if advisories.present?
      severity::ALERT.include?(severity.worst(advisories)) ? 'alert' : 'vulnerable'
    elsif item['eol']
      'alert'
    elsif stronger_outdated?(item)
      'outdated'
    elsif advisories.nil? && item['branch_latest'].nil? && item['latest'].nil? && item['up_to_date'].nil?
      'unknown'
    else
      'ok'
    end
  end

  # A newer release is actually available. The support phase alone
  # (security only) is shown by the support badge, not here.
  def stronger_outdated?(item)
    newer = item['branch_latest'] || (item['kind'] == 'javascript' && item['latest'])
    (newer.present? && newer != item['version']) || item['candidate'].present? || item['up_to_date'] == false
  end

  def stronger_version_tag(item)
    content_tag(:span, item['version'], class: "stronger-version stronger-version-#{stronger_item_status(item)}")
  end

  # Per category: number of items, vulnerable ones and outdated ones.
  def stronger_category_summaries(report)
    StrongerDependencyReport::CATEGORIES.filter_map do |category|
      items = report.items(category)
      next if items.empty?

      statuses = items.map { |item| stronger_item_status(item) }
      vulnerable = statuses.count { |s| %w(alert vulnerable).include?(s) }
      outdated = statuses.count('outdated')
      unknown = statuses.count('unknown')
      status =
        if statuses.include?('alert') then 'alert'
        elsif vulnerable > 0 then 'vulnerable'
        elsif outdated > 0 then 'outdated'
        elsif unknown > 0 then 'unknown'
        else 'ok'
        end
      { category: category, total: items.size, vulnerable: vulnerable, outdated: outdated, unknown: unknown,
        status: status }
    end
  end

  def stronger_dependency_tiles(report)
    stronger_category_summaries(report).map do |summary|
      details = []
      details << l(:stronger_tile_vulnerable, count: summary[:vulnerable]) if summary[:vulnerable] > 0
      details << l(:stronger_tile_outdated, count: summary[:outdated]) if summary[:outdated] > 0
      details << l(:stronger_tile_unknown, count: summary[:unknown]) if summary[:unknown] > 0
      details << l(:stronger_tile_ok) if summary[:status] == 'ok'
      { anchor: "stronger-#{summary[:category]}", title: l("stronger_category_#{summary[:category]}"),
        count: summary[:total], status: summary[:status], details: details }
    end
  end

  # Tiles of the accounts and permissions tab. Anonymous exposure and
  # inactive administrators are alerts, the other findings need a review.
  def stronger_overview_tiles(anon:, anon_open:, non_member:, non_member_open:, wikis:, wiki_projects:,
                              inactive:, inactive_admins:, locked:, api:, api_blocked: 0, documentations: nil,
                              documentation_projects: nil)
    exposure = lambda do |name, count, open, status|
      details = count > 0 ? [l(:stronger_tile_open_issues, count: open)] : [l(:stronger_tile_not_exposed)]
      stronger_tile(name, count, count > 0 ? status : 'ok', details)
    end
    opened = lambda do |name, count, total|
      details = count > 0 ? [l(:stronger_tile_projects_of, total: total)] : [l(:stronger_tile_not_exposed)]
      stronger_tile(name, count, count > 0 ? 'vulnerable' : 'ok', details)
    end

    tiles = [
      exposure.call('anon', anon, anon_open, 'alert'),
      exposure.call('non_member', non_member, non_member_open, 'vulnerable'),
      opened.call('wikis', wikis, wiki_projects)
    ]
    tiles << opened.call('documentations', documentations, documentation_projects) if documentations
    inactive_status =
      if inactive_admins > 0 then 'alert'
      elsif inactive > 0 then 'outdated'
      else 'ok'
      end
    inactive_details = inactive_admins > 0 ? [l(:stronger_tile_inactive_admins, count: inactive_admins)] : []
    tiles << stronger_tile('inactive', inactive, inactive_status, inactive_details)
    period = l(:stronger_tile_api_period, days: RedmineStronger::SecurityMetrics::API_RECENT_DAYS)
    tiles << if api_blocked > 0
               stronger_tile('api', api, 'vulnerable', [period, l(:stronger_tile_api_blocked, count: api_blocked)])
             elsif api > 0
               stronger_tile('api', api, 'unknown', [period, l(:stronger_tile_api_detail, count: api)])
             else
               stronger_tile('api', api, 'ok', [period, l(:stronger_tile_no_api)])
             end
    tiles << stronger_tile('locked', locked, locked > 0 ? 'outdated' : 'ok', [])
  end

  def stronger_tile(name, count, status, details)
    { anchor: "stronger-#{name.dasherize}", title: l("stronger_tile_#{name}"), count: count, status: status,
      details: details }
  end

  # Inactive administrators stand out, accounts that never logged in come next.
  def stronger_user_row_status(user)
    if user.admin? || (user.respond_to?(:sudoer?) && user.sudoer?)
      'alert'
    elsif user.last_login_on.nil?
      'outdated'
    end
  end

  # The prefilled form travels in the query string: bounded to stay well
  # below the request line limits of web servers.
  STRONGER_ISSUE_MAX_ADVISORIES = 10
  STRONGER_ISSUE_MAX_DESCRIPTION = 3000

  # Shortcut to a new issue describing the update, for items needing action.
  def stronger_new_issue_link(item, report)
    return unless %w(alert vulnerable outdated).include?(stronger_item_status(item))

    issue = { subject: stronger_issue_subject(item),
              description: stronger_issue_description(item, report).truncate(STRONGER_ISSUE_MAX_DESCRIPTION) }
    link_to sprite_icon('add'), new_issue_path(issue: issue),
            class: 'icon-only icon-add', title: l(:stronger_issue_new)
  end

  # Version to move to: apt candidate, then the latest release of the
  # installed branch, unless that branch is no longer supported.
  def stronger_target_version(item)
    candidates = [item['candidate']]
    candidates += item['eol'] ? [item['latest']] : [item['branch_latest'], item['latest']]
    candidates.find { |version| version.present? && version != item['version'] }
  end

  def stronger_issue_component(item)
    kind = item['kind'].to_s
    %w(gem javascript package plugin).include?(kind) ? "#{item['name']} (#{l("stronger_issue_kind_#{kind}")})" : item['name']
  end

  def stronger_issue_subject(item)
    component = stronger_issue_component(item)
    target = stronger_target_version(item)
    subject =
      if target
        l(:stronger_issue_subject_target, component: component, version: item['version'], target: target)
      else
        l(:stronger_issue_subject, component: component, version: item['version'])
      end
    advisories = Array(item['advisories'])
    if advisories.any?
      l(:stronger_label_value, label: subject, value: l(:stronger_issue_subject_advisories, count: advisories.size))
    elsif item['eol']
      l(:stronger_label_value, label: subject, value: l(:stronger_support_eol))
    else
      subject
    end
  end

  # Technical details for the maintainer, as a list readable in Textile and
  # Markdown alike.
  def stronger_issue_description(item, report)
    field = ->(label, value) { "* #{l(:stronger_label_value, label: l(label), value: value)}" }
    target = stronger_target_version(item)
    lines = []
    lines << field.call(:stronger_column_component, stronger_issue_component(item))
    if item['kind'] == 'gem'
      dependency = item['direct'] ? :stronger_issue_dependency_direct : :stronger_issue_dependency_transitive
      lines << field.call(:stronger_issue_dependency, l(dependency))
    end
    lines << field.call(:stronger_issue_installed, item['version'])
    lines << field.call(:stronger_issue_target, target) if target
    lines << field.call(:stronger_column_branch_latest, item['branch_latest']) if item['branch_latest'].present? && item['branch_latest'] != target
    lines << field.call(:stronger_column_latest, item['latest']) if item['latest'].present? && item['latest'] != target
    lines << field.call(:stronger_column_support, stronger_issue_support(item)) if item['cycle']
    lines << field.call(:stronger_issue_path, item['path']) if item['path'].present?
    lines << field.call(:stronger_issue_binaries, Array(item['binaries']).join(', ')) if item['binaries'].present?
    if item['kind'] == 'plugin'
      local = [item['branch'], stronger_short_commit(item['commit']), item['commit_date']&.to_date&.then { |d| format_date(d) }]
      lines << field.call(:stronger_issue_local_commit, local.compact.join(' ')) if item['commit']
      lines << field.call(:stronger_issue_upstream, item['remote']) if item['remote'].present?
      lines << field.call(:stronger_issue_upstream_commit, stronger_short_commit(item['remote_commit'])) if item['remote_commit']
    end
    command = stronger_issue_command(item)
    lines << field.call(:stronger_issue_command, command) if command

    severity = RedmineStronger::DependencyAudit::Severity
    advisories = Array(item['advisories']).sort_by { |advisory| severity.rank(advisory['severity']) }
    if advisories.any?
      lines += ['', l(:stronger_dependencies_advisories_summary), '']
      advisories.first(STRONGER_ISSUE_MAX_ADVISORIES).each { |advisory| lines << stronger_issue_advisory(advisory) }
      if advisories.size > STRONGER_ISSUE_MAX_ADVISORIES
        lines << "* #{l(:stronger_issue_more_advisories, count: advisories.size - STRONGER_ISSUE_MAX_ADVISORIES)}"
      end
    end

    environment = report.items('environment').map do |env|
      env['name'].to_s.include?(env['version'].to_s) ? env['name'] : "#{env['name']} #{env['version']}"
    end.join(', ')
    lines += ['', l(:stronger_label_value, label: l(:stronger_issue_environment), value: environment)] if environment.present?
    lines << l(:stronger_issue_footer, date: format_date(report.collected_at), url: stronger_security_dependencies_url)
    lines.join("\n")
  end

  def stronger_issue_support(item)
    status = if item['eol'] then 'eol'
             elsif item['security_only'] then 'security_only'
             else 'supported'
             end
    support = "#{l("stronger_support_#{status}")} (#{item['cycle']})"
    item['eol_date'] ? "#{support}, #{l(:stronger_support_until, date: format_date(item['eol_date'].to_date))}" : support
  end

  # Indicative command, to be checked by the maintainer.
  def stronger_issue_command(item)
    case item['kind']
    when 'gem' then "bundle update --conservative #{item['name']}"
    when 'package' then "apt-get install --only-upgrade #{Array(item['binaries']).join(' ')}" if item['candidate']
    when 'plugin' then "git -C #{item['path']} pull" if item['up_to_date'] == false && item['path']
    end
  end

  def stronger_issue_advisory(advisory)
    ids = [advisory['id'], advisory['ghsa']].compact.uniq.join(' / ')
    facts = [l("stronger_severity_#{advisory['severity']}")]
    facts << "CVSS #{advisory['cvss']}" if advisory['cvss']
    facts << l(:stronger_issue_published, date: advisory['date']) if advisory['date'].present?
    line = "* #{ids} (#{facts.join(', ')})"
    line = l(:stronger_label_value, label: line, value: advisory['title'].truncate(150)) if advisory['title'].present?
    fixed = Array(advisory['fixed']).join(', ')
    line += ". #{l(:stronger_fixed_in, versions: fixed).upcase_first}" if fixed.present?
    line += ". #{advisory['url']}" if advisory['url'].to_s.match?(%r{\Ahttps?://}i)
    line
  end

  # Vulnerable items first (most severe first), then by name.
  def stronger_sorted_items(items)
    items.sort_by do |item|
      advisories = Array(item['advisories'])
      worst = RedmineStronger::DependencyAudit::Severity.worst(advisories)
      [advisories.empty? ? 1 : 0, RedmineStronger::DependencyAudit::Severity.rank(worst), item['name'].to_s]
    end
  end

  # Number of advisories per severity, over every category.
  def stronger_severity_counts(report)
    counts = Hash.new(0)
    StrongerDependencyReport::CATEGORIES.each do |category|
      report.items(category).each do |item|
        Array(item['advisories']).each { |advisory| counts[advisory['severity']] += 1 }
      end
    end
    counts
  end

  def stronger_unsupported_components(report)
    report.items('environment').select { |item| item['eol'] }
  end

  # Advisory urls come from external data: only http(s) links are rendered.
  def stronger_advisory_link(advisory)
    url = advisory['url'].to_s
    return advisory['id'] unless url.match?(%r{\Ahttps?://}i)

    link_to(advisory['id'], url, class: 'external', target: '_blank', rel: 'noopener noreferrer')
  end

  # The audit is complete when every source ran without error.
  def stronger_dependencies_complete?(report)
    report.source_errors.empty? &&
      (RedmineStronger::DependencyAudit::Collector::SOURCES - Array(report.payload['sources'])).empty?
  end

  def stronger_short_commit(sha)
    sha.to_s[0, 8]
  end
end
