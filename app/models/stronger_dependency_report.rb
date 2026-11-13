# frozen_string_literal: true

# Snapshot of the dependency audit, written by the collector
# (rake redmine:stronger:audit_dependencies) and read by the dashboard.
# A collection requested from the dashboard is a row that goes from
# running to done (or failed).
class StrongerDependencyReport < ActiveRecord::Base
  KEPT_REPORTS = 10
  STALE_AFTER  = 7.days
  # A running collection older than this is considered abandoned.
  RUN_TIMEOUT  = 1.hour

  CATEGORIES = %w(environment gems javascripts plugins packages).freeze

  STATUS_RUNNING = 'running'
  STATUS_DONE    = 'done'
  STATUS_FAILED  = 'failed'

  validates :status, inclusion: { in: [STATUS_RUNNING, STATUS_DONE, STATUS_FAILED] }
  validates :collected_at, :data, presence: true, if: :done?

  scope :done, -> { where(status: STATUS_DONE) }

  def self.latest
    done.order(collected_at: :desc).first
  end

  # The last collection requested from the dashboard.
  def self.last_request
    where.not(requested_at: nil).order(requested_at: :desc).first
  end

  # Running and not abandoned.
  def self.running
    request = last_request
    request if request&.running? && !request.expired?
  end

  # Failed or abandoned.
  def self.failed_request
    request = last_request
    request if request&.failed? || (request&.running? && request.expired?)
  end

  def self.request!
    report = create!(status: STATUS_RUNNING, requested_at: Time.current)
    prune
    report
  end

  def self.record!(payload, duration: nil, report: nil)
    report ||= new
    report.update!(status: STATUS_DONE, collected_at: Time.current, duration: duration, data: JSON.generate(payload),
                   error: nil)
    prune
    report
  end

  def self.prune
    # Ids plucked first: MySQL rejects LIMIT inside an IN subquery.
    kept = done.order(collected_at: :desc).limit(KEPT_REPORTS).pluck(:id)
    done.where.not(id: kept).delete_all
    # Only the last request matters, to show it running or failed.
    request = last_request
    where.not(status: STATUS_DONE).where.not(id: request.id).delete_all if request
  end

  def fail!(message)
    update!(status: STATUS_FAILED, error: message.to_s.truncate(1000))
  end

  def running?
    status == STATUS_RUNNING
  end

  def done?
    status == STATUS_DONE
  end

  def failed?
    status == STATUS_FAILED
  end

  def expired?
    requested_at < RUN_TIMEOUT.ago
  end

  def payload
    @payload ||= JSON.parse(data)
  end

  def items(category)
    Array(payload[category])
  end

  def source_errors
    Array(payload['errors'])
  end

  def stale?
    collected_at < STALE_AFTER.ago
  end
end
