# frozen_string_literal: true

namespace :redmine do
  namespace :stronger do
    desc <<~DESC
      Audit the dependencies (system, Ruby, Rails, Redmine, database, gems, JavaScript, plugins)
      and record a snapshot for the security dashboard.

      Network access goes through the proxy of the environment (https_proxy, no_proxy).

      Options:
        ONLY=a,b        only these sources: advisories, rubygems, endoflife, nvd, debian, npm, osv, git
        OFFLINE=1       local inventory only, no network access

      Exits with status 2 when a critical or high advisory is found,
      1 when a source failed (the snapshot is recorded but incomplete).
    DESC
    task audit_dependencies: :environment do
      collector_class = RedmineStronger::DependencyAudit::Collector
      sources = ENV['ONLY'].present? ? ENV['ONLY'].split(',').map(&:strip) : collector_class::SOURCES
      unknown = sources - collector_class::SOURCES
      abort "Unknown sources: #{unknown.join(', ')} (available: #{collector_class::SOURCES.join(', ')})" if unknown.any?

      collector = collector_class.new(sources: sources, offline: ENV['OFFLINE'] == '1')

      started_at = Time.now
      payload = collector.run
      duration = Time.now - started_at
      # REPORT_ID: request from the dashboard, completed by this run.
      request = StrongerDependencyReport.find_by(id: ENV['REPORT_ID']) if ENV['REPORT_ID'].present?
      StrongerDependencyReport.record!(payload, duration: duration, report: request)

      counts = StrongerDependencyReport::CATEGORIES.map do |category|
        items = Array(payload[category])
        "#{items.count { |i| i['advisories'].present? }}/#{items.size} #{category}"
      end
      puts "Dependency audit recorded in #{ActiveSupport::Duration.build(duration.round).inspect}: " \
           "vulnerable #{counts.join(', ')}"
      collector.errors.each { |error| puts "  #{error['source']}: #{error['message']}" }

      exit 2 if collector_class.alert_count(payload) > 0
      exit 1 if collector.errors.any?
    end
  end
end
