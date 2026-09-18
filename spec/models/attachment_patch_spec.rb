# frozen_string_literal: true

require "spec_helper"
require "tmpdir"

describe Attachment do
  fixtures :users

  let(:scanner) { RedmineStronger::MalwareScanner }
  let(:storage_path) { Dir.mktmpdir }

  around do |example|
    saved_path = Attachment.storage_path
    Attachment.storage_path = storage_path
    example.run
  ensure
    Attachment.storage_path = saved_path
    FileUtils.remove_entry(storage_path)
  end

  def set_malware_scan(value)
    Setting["plugin_redmine_stronger"] =
      Setting["plugin_redmine_stronger"].merge("malware_scan" => value)
  end

  def new_attachment(file = StringIO.new("file content"))
    Attachment.new(file: file, filename: "report.docx", author: User.find(1))
  end

  def stored_files
    Dir.glob(File.join(storage_path, "**", "*")).select { |path| File.file?(path) }
  end

  before { set_malware_scan("1") }
  after { set_malware_scan("") }

  it "does not scan uploads when the scan is disabled" do
    set_malware_scan("")
    expect(scanner).not_to receive(:scan)

    expect(new_attachment.save).to be true
  end

  it "stores a clean file with its full content" do
    allow(scanner).to receive(:scan) { |io| io.read && nil }

    attachment = new_attachment
    expect(attachment.save).to be true
    expect(File.read(attachment.diskfile)).to eq("file content")
    expect(scanner).to have_received(:scan).once
  end

  it "rejects an infected file before writing it to disk" do
    allow(scanner).to receive(:scan).and_return("Eicar-Test-Signature")

    attachment = new_attachment
    expect(attachment.save).to be false
    expect(attachment.errors.full_messages.join).to include("Eicar-Test-Signature")
    expect(stored_files).to be_empty
  end

  it "accepts the file and defers the scan when clamd is unavailable" do
    allow(scanner).to receive(:scan).and_raise(scanner::Unavailable, "ENOENT")
    expect(StrongerMalwareScanJob).to receive(:perform_later).with(kind_of(Integer))

    expect(new_attachment.save).to be true
  end

  it "accepts the file without deferring the scan when clamd cannot scan it" do
    allow(scanner).to receive(:scan).and_raise(scanner::Error, "INSTREAM size limit exceeded. ERROR")
    expect(StrongerMalwareScanJob).not_to receive(:perform_later)

    expect(new_attachment.save).to be true
  end

  it "defers the scan of a stream that cannot be rewound" do
    stream = StringIO.new("piped content")
    stream.singleton_class.undef_method(:rewind)
    expect(scanner).not_to receive(:scan)
    expect(StrongerMalwareScanJob).to receive(:perform_later).with(kind_of(Integer))

    attachment = new_attachment(stream)
    expect(attachment.save).to be true
    expect(File.read(attachment.diskfile)).to eq("piped content")
  end
end
