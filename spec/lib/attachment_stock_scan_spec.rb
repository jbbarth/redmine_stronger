# frozen_string_literal: true

require "spec_helper"
require "tmpdir"

describe RedmineStronger::AttachmentStockScan do
  fixtures :users

  let(:scanner) { RedmineStronger::MalwareScanner }
  let(:storage_path) { Dir.mktmpdir }
  let(:stock_scan) { described_class.new(socket: "clamd.ctl", threads: 2) }

  around do |example|
    saved_path = Attachment.storage_path
    Attachment.storage_path = storage_path
    example.run
  ensure
    Attachment.storage_path = saved_path
    FileUtils.remove_entry(storage_path)
  end

  before do
    Attachment.delete_all
    allow(scanner).to receive(:scan) do |file, socket:|
      case file.read
      when /\Ainfected/ then "Eicar-Test-Signature"
      when "huge" then raise scanner::Error, "INSTREAM size limit exceeded. ERROR"
      end
    end
  end

  def create_attachment(content, filename: "#{content}.txt")
    Attachment.create!(file: StringIO.new(content), filename: filename, author: User.find(2))
  end

  it "sorts every stored file into clean, infected, not scannable and unreadable" do
    create_attachment("clean")
    create_attachment("infected")
    create_attachment("huge")
    File.delete(create_attachment("deleted").diskfile)

    stock_scan.run

    expect(stock_scan.counts).to eq(clean: 1, infected: 1, unscanned: 1, unreadable: 1)
  end

  it "scans a file shared by several attachments once and reports each attachment" do
    original = create_attachment("infected")
    copy = create_attachment("other", filename: "copy.txt")
    File.delete(copy.diskfile)
    copy.update_columns(disk_directory: original.disk_directory, disk_filename: original.disk_filename)

    stock_scan.run
    report = File.join(storage_path, "report.csv")
    stock_scan.write_report(report)

    expect(scanner).to have_received(:scan).once
    rows = CSV.read(report, headers: true)
    reported = rows.map { |row| [row["status"], row["detail"], row["filename"], row["author"]] }
    expect(reported).to eq([["infected", "Eicar-Test-Signature", "infected.txt", "jsmith"],
                            ["infected", "Eicar-Test-Signature", "copy.txt", "jsmith"]])
  end

  it "only scans the attachments created in the last SINCE days" do
    create_attachment("infected").update_column(:created_on, 10.days.ago)
    create_attachment("clean")

    scan = described_class.new(socket: "clamd.ctl", threads: 2, since: 7)
    scan.run

    expect(scan.counts).to eq(clean: 1)
  end

  it "sends one summary notification whatever the number of infected files" do
    3.times { |i| create_attachment("infected #{i}") }
    ActionMailer::Base.deliveries.clear

    stock_scan.run
    stock_scan.notify_administrators("/var/log/malware_scan.csv")

    expect(ActionMailer::Base.deliveries.map(&:to).flatten.uniq).to eq(User.active.where(admin: true).map(&:mail))
    mail = ActionMailer::Base.deliveries.last
    expect(mail.text_part.body.to_s).to include("3 (/var/log/malware_scan.csv)")
  end

  it "refuses to run when the attachment storage is empty or not mounted" do
    create_attachment("clean")
    FileUtils.remove_entry(storage_path)
    FileUtils.mkdir_p(storage_path)

    expect { stock_scan.run }.to raise_error(described_class::StorageUnavailable, storage_path)
    expect(scanner).not_to have_received(:scan)
  end

  it "carries on when clamd takes too long on one file" do
    create_attachment("clean")
    create_attachment("slow")
    allow(scanner).to receive(:scan) do |file, socket:|
      raise scanner::Timeout, "IO::TimeoutError" if file.read == "slow"
    end

    stock_scan.run

    expect(stock_scan.counts).to eq(clean: 1, unscanned: 1)
  end

  it "stops when clamd becomes unavailable" do
    3.times { |i| create_attachment("clean #{i}") }
    allow(scanner).to receive(:scan).and_raise(scanner::Unavailable, "ECONNREFUSED")

    expect { stock_scan.run }.to raise_error(scanner::Unavailable, "ECONNREFUSED")
    expect(stock_scan.counts.values.sum).to eq(0)
  end
end
