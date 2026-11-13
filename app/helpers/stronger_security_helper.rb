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
