# frozen_string_literal: true

module RedmineStronger
  module AttachmentPatch
    private

    def stronger_scan_for_malware
      return unless errors.empty? && RedmineStronger::MalwareScanner.enabled?

      source = @temp_file
      unless source.is_a?(String) || source.respond_to?(:rewind)
        @stronger_deferred_scan = true
        return
      end

      begin
        signature = RedmineStronger::MalwareScanner.scan(source)
      rescue RedmineStronger::MalwareScanner::Unavailable => e
        Rails.logger.warn "[redmine_stronger] clamd unavailable, deferring scan of #{filename}: #{e.message}"
        @stronger_deferred_scan = true
      rescue RedmineStronger::MalwareScanner::Error => e
        Rails.logger.warn "[redmine_stronger] #{filename} could not be scanned: #{e.message}"
      ensure
        source.rewind unless source.is_a?(String)
      end

      if signature
        Rails.logger.warn "[redmine_stronger] upload of #{filename} by #{author&.login} rejected: #{signature}"
        errors.add(:base, l(:stronger_error_attachment_infected, signature: signature))
      end
    end

    def stronger_enqueue_deferred_scan
      StrongerMalwareScanJob.perform_later(id) if @stronger_deferred_scan
    end
  end
end

Attachment.prepend RedmineStronger::AttachmentPatch

unless Attachment._validate_callbacks.map(&:filter).include?(:stronger_scan_for_malware)
  Attachment.validate :stronger_scan_for_malware, if: -> { @temp_file }
  Attachment.after_commit :stronger_enqueue_deferred_scan, on: :create
end
