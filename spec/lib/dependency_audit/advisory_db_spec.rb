# frozen_string_literal: true

require "spec_helper"

describe RedmineStronger::DependencyAudit::AdvisoryDb do
  def archive(files)
    io = StringIO.new
    Zlib::GzipWriter.wrap(io) do |gzip|
      Gem::Package::TarWriter.new(gzip) do |tar|
        files.each do |path, content|
          tar.add_file_simple(path, 0o644, content.bytesize) { |f| f.write(content) }
        end
      end
    end
    io.string
  end

  let(:advisory) do
    {
      "gem" => "rack", "cve" => "2026-0001", "ghsa" => "abcd-efgh-ijkl", "title" => "Bad thing",
      "url" => "https://example.org/advisory", "cvss_v3" => 7.5,
      "patched_versions" => ["~> 3.1.20", ">= 3.2.7"], "unaffected_versions" => ["< 2.0.0"]
    }
  end

  let(:ruby_advisory) { { "engine" => "ruby", "cve" => "2026-0002", "patched_versions" => [">= 4.0.9"] } }

  let(:db) do
    files = {
      "ruby-advisory-db-master/gems/rack/CVE-2026-0001.yml" => advisory.to_yaml,
      "ruby-advisory-db-master/rubies/ruby/CVE-2026-0002.yml" => ruby_advisory.to_yaml,
      "ruby-advisory-db-master/README.md" => "not an advisory"
    }
    described_class.new(described_class.parse_archive(archive(files)))
  end

  it "indexes the gem and ruby advisories of the archive" do
    expect(db.size).to eq 2
  end

  it "reports a version that is neither patched nor unaffected" do
    expect(db.for_gem("rack", "3.2.6").pluck("id")).to eq ["CVE-2026-0001"]
    expect(db.for_gem("rack", "3.1.19")).not_to be_empty
  end

  it "ignores patched versions, on every patched branch" do
    expect(db.for_gem("rack", "3.2.7")).to be_empty
    expect(db.for_gem("rack", "3.1.20")).to be_empty
  end

  it "ignores unaffected versions" do
    expect(db.for_gem("rack", "1.6.0")).to be_empty
  end

  it "treats a prerelease of a patched version as vulnerable" do
    expect(db.for_gem("rack", "3.2.7.beta1")).not_to be_empty
  end

  it "returns nothing for a gem without advisory" do
    expect(db.for_gem("rails", "8.1.4.1")).to be_empty
  end

  it "matches the ruby interpreter advisories" do
    expect(db.for_ruby("ruby", "4.0.5").pluck("id")).to eq ["CVE-2026-0002"]
    expect(db.for_ruby("ruby", "4.0.9")).to be_empty
  end

  it "normalizes the advisory with a severity derived from CVSS" do
    expect(db.for_gem("rack", "3.2.6").first).to include(
      "cve" => "CVE-2026-0001", "ghsa" => "GHSA-abcd-efgh-ijkl", "severity" => "high",
      "fixed" => ["~> 3.1.20", ">= 3.2.7"], "fix_available" => true
    )
  end
end
