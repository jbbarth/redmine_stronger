# frozen_string_literal: true

require 'open3'

# Dependency audit requested from the dashboard. The collection runs in a
# child process (the rake task), so that its memory peak (Debian tracker)
# is released when it ends instead of staying in the long-lived worker.
class StrongerDependencyAuditJob < ApplicationJob
  TASK = 'redmine:stronger:audit_dependencies'

  def perform(report_id)
    report = StrongerDependencyReport.find_by(id: report_id)
    return unless report&.running?

    output, status = run_task(report)
    report.reload
    return if report.done?

    Rails.logger.error "[redmine_stronger] dependency audit failed: #{output}"
    report.fail!(failure_summary(output).presence || "exit status #{status&.exitstatus}")
  rescue => e
    report&.fail!(e.message)
    raise
  end

  BACKTRACE_LINE = /\A\s*\S+:\d+:in /

  # The end of a rake failure is its backtrace: keep the message lines.
  def failure_summary(output)
    lines = output.to_s.lines.map(&:rstrip).reject do |line|
      line.blank? || line.match?(BACKTRACE_LINE) || line.start_with?('(See full trace')
    end
    lines.last(5).join("\n")
  end

  def run_task(report)
    env = { 'RAILS_ENV' => Rails.env, 'REPORT_ID' => report.id.to_s }
    Open3.popen2e(env, Gem.ruby, Rails.root.join('bin/rails').to_s, TASK, chdir: Rails.root.to_s) do |stdin, out, wait|
      stdin.close
      reader = Thread.new { out.read }
      unless wait.join(StrongerDependencyReport::RUN_TIMEOUT.to_i)
        Process.kill('TERM', wait.pid)
        wait.join
        return ["Timed out after #{StrongerDependencyReport::RUN_TIMEOUT.inspect}", nil]
      end
      [reader.value.to_s, wait.value]
    end
  end
end
