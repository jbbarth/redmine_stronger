# frozen_string_literal: true

require 'csv'

module RedmineStronger
  # Scans the attachment files already stored on disk, each distinct file once
  class AttachmentStockScan
    class StorageUnavailable < StandardError; end

    REPORT_HEADERS = %w(status detail attachment_id filename filesize created_on author project container_type container_id diskfile).freeze
    REPORT_BATCH = 500

    attr_reader :counts, :findings

    def initialize(socket:, threads: 4, since: nil)
      @socket = socket
      @threads = threads
      @since = since
      @counts = Hash.new(0)
      @findings = []
      @mutex = Mutex.new
    end

    def total
      attachments.count
    end

    # Yields the number of files processed so far after each file.
    # Raises MalwareScanner::Unavailable if clamd stops answering.
    def run(&progress)
      storage_path = Attachment.storage_path
      unless File.directory?(storage_path) && !Dir.empty?(storage_path)
        raise StorageUnavailable, storage_path
      end

      queue = SizedQueue.new(@threads * 4)
      workers = Array.new(@threads) { Thread.new { work(queue, &progress) } }
      each_stored_file do |stored_file|
        break if @failure

        queue << stored_file
      end
      @threads.times { queue << nil }
      workers.each(&:join)
      raise @failure if @failure
    end

    def write_report(path)
      CSV.open(path, 'w') do |csv|
        csv << REPORT_HEADERS
        findings.sort_by {|finding| finding[:status]}.each_slice(REPORT_BATCH) do |slice|
          attachments = reported_attachments(slice)
          slice.each do |finding|
            attachments[stored_file_key(finding[:stored_file])]&.each do |attachment|
              csv << [finding[:status], finding[:detail], attachment.id, attachment.filename, attachment.filesize,
                      attachment.created_on, attachment.author&.login, attachment.project&.identifier,
                      attachment.container_type, attachment.container_id, attachment.diskfile]
            end
          end
        end
      end
    end

    # Sends a single summary notification to the administrators, whatever the number of findings
    def notify_administrators(report_path)
      Mailer.deliver_security_notification(
        User.active.where(admin: true).to_a,
        User.anonymous,
        message: :stronger_mail_body_stock_scan_infected,
        value: "#{counts[:infected]} (#{report_path})"
      )
    end

    private

    # Attachments of the given findings, indexed by stored file, with their author and project loaded
    def reported_attachments(findings)
      attachments = Attachment.where(disk_filename: findings.map {|finding| finding[:stored_file][:disk_filename]})
                              .order(:id).includes(:author, :container).to_a
      attachments.filter_map(&:container).group_by(&:class).each do |container_class, containers|
        next unless container_class.reflect_on_association(:project)

        ActiveRecord::Associations::Preloader.new(records: containers, associations: :project).call
      end
      attachments.group_by {|attachment| stored_file_key(disk_directory: attachment.disk_directory, disk_filename: attachment.disk_filename)}
    end

    def stored_file_key(stored_file)
      [stored_file[:disk_directory].to_s, stored_file[:disk_filename].to_s]
    end

    def attachments
      scope = Attachment.where.not(disk_filename: [nil, ''])
      scope = scope.where(created_on: @since.days.ago..) if @since
      scope
    end

    def each_stored_file
      seen = Set.new
      attachments.in_batches(of: 1000) do |batch|
        batch.pluck(:disk_directory, :disk_filename).each do |directory, filename|
          stored_file = {disk_directory: directory, disk_filename: filename}
          yield stored_file if seen.add?(stored_file_key(stored_file))
        end
      end
    end

    def work(queue, &progress)
      while (stored_file = queue.pop)
        next if @failure

        status, detail = scan(stored_file)
        @mutex.synchronize do
          @counts[status] += 1
          @findings << {status: status, detail: detail, stored_file: stored_file} unless status == :clean
          progress&.call(@counts.values.sum)
        end
      end
    rescue MalwareScanner::Unavailable => e
      @mutex.synchronize { @failure ||= e }
      retry
    end

    def scan(stored_file)
      path = File.join(Attachment.storage_path, stored_file[:disk_directory].to_s, stored_file[:disk_filename])
      signature = File.open(path, 'rb') {|file| MalwareScanner.scan(file, socket: @socket)}
      signature ? [:infected, signature] : [:clean]
    rescue MalwareScanner::Timeout, MalwareScanner::Error => e
      [:unscanned, e.message]
    rescue SystemCallError => e
      [:unreadable, e.class.name]
    end
  end
end
