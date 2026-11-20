# frozen_string_literal: true

require "spec_helper"

describe RedmineStronger::DependencyAudit::Sources::Rubygems do
  let(:info) do
    <<~INFO
      ---
      3.2.5 |checksum:a
      3.2.6 |checksum:b
      3.2.7-x86_64-linux |checksum:c
      3.3.0.rc1 |checksum:d
      4.0.1 |checksum:e
    INFO
  end

  it "reads released versions of the compact index, without platforms nor prereleases" do
    expect(described_class.parse_info(info).map(&:to_s)).to eq %w(3.2.5 3.2.6 3.2.7 4.0.1)
  end

  it "gives the latest version overall and in the installed branch" do
    summary = described_class.summarize(described_class.parse_info(info), "3.2.6")
    expect(summary).to eq("latest" => "4.0.1", "branch_latest" => "3.2.7")
  end
end

describe RedmineStronger::DependencyAudit::Sources::EndOfLife do
  let(:releases) do
    [
      { "name" => "8.1", "releaseDate" => "2025-10-22", "isEol" => false, "isEoas" => true,
        "eolFrom" => "2027-10-10", "latest" => { "name" => "8.1.4.1" } },
      { "name" => "8.0", "releaseDate" => "2024-11-07", "isEol" => true, "isEoas" => true,
        "eolFrom" => "2026-11-07", "latest" => { "name" => "8.0.5.2" } }
    ]
  end

  it "finds the release cycle of a version" do
    expect(described_class.release_for(releases, "8.0.3")["name"]).to eq "8.0"
    expect(described_class.release_for(releases, "7.2.1")).to be_nil
  end

  it "flags an end of life cycle" do
    expect(described_class.summarize(releases, "8.0.3"))
      .to include("cycle" => "8.0", "branch_latest" => "8.0.5.2", "latest" => "8.1.4.1", "eol" => true, "security_only" => false)
  end

  it "flags a cycle that only receives security fixes" do
    expect(described_class.summarize(releases, "8.1.4.1")).to include("eol" => false, "security_only" => true)
  end
end

describe RedmineStronger::DependencyAudit::Sources::Osv do
  it "normalizes an OSV vulnerability with its fixed versions for the package" do
    vuln = {
      "id" => "GHSA-aaaa-bbbb-cccc", "aliases" => ["CVE-2024-0001"], "summary" => "XSS in tinymce",
      "database_specific" => { "severity" => "MODERATE" },
      "affected" => [{ "package" => { "name" => "tinymce" }, "ranges" => [{ "events" => [{ "introduced" => "0" }, { "fixed" => "5.10.9" }] }] }]
    }
    expect(described_class.normalize(vuln, "tinymce")).to include(
      "id" => "CVE-2024-0001", "ghsa" => "GHSA-aaaa-bbbb-cccc", "severity" => "medium",
      "fixed" => [">= 5.10.9"], "fix_available" => true
    )
  end
end

describe RedmineStronger::DependencyAudit::Sources::Osv, "with unreachable details" do
  it "still reports a vulnerability whose details could not be fetched" do
    http = double("http")
    allow(http).to receive(:post_json).and_return("results" => [{ "vulns" => [{ "id" => "GHSA-x" }] }])
    allow(http).to receive(:get_json).and_raise(RedmineStronger::DependencyAudit::Http::Error, "HTTP 503")
    osv = described_class.new(http)

    found = osv.advisories([%w(tinymce 4.9.11)])
    expect(found[%w(tinymce 4.9.11)]).to contain_exactly(include("id" => "GHSA-x", "severity" => "unknown"))
    expect(osv.errors).to eq ["HTTP 503"]
  end
end

describe RedmineStronger::DependencyAudit::Inventory do
  let(:inventory) { described_class.new }

  it "parses os-release" do
    info = inventory.parse_os_release(%(PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\nVERSION_ID="11"\nVERSION_CODENAME=bullseye\nID=debian\n))
    expect(info).to include("id" => "debian", "version_id" => "11", "version_codename" => "bullseye")
  end

  it "reads the point release of the system" do
    ubuntu = { "id" => "ubuntu", "version_id" => "24.04", "version" => "24.04.5 LTS (Noble Numbat)" }
    expect(inventory.os_point_release(ubuntu)).to eq "24.04.5"

    Tempfile.create("debian_version") do |file|
      debian = { "id" => "debian", "version_id" => "11", "version" => "11 (bullseye)" }
      file.write("11.11\n")
      file.flush
      expect(inventory.os_point_release(debian, debian_version_path: file.path)).to eq "11.11"

      file.truncate(0)
      file.rewind
      file.write("trixie/sid\n")
      file.flush
      expect(inventory.os_point_release(debian, debian_version_path: file.path)).to eq "11"
    end
  end

  it "reads apt candidates only for installed packages" do
    output = <<~APT
      libxml2:
        Installed: 2.9.10+dfsg-6.7+deb11u4
        Candidate: 2.9.10+dfsg-6.7+deb11u5
        Version table:
      nginx:
        Installed: (none)
        Candidate: 1.18.0-6.1
    APT
    expect(inventory.parse_apt_policy(output)).to eq("libxml2" => "2.9.10+dfsg-6.7+deb11u5")
  end

  it "detects a library from its license banner, not from a mention in another library" do
    Dir.mktmpdir do |dir|
      jquery = File.join(dir, "jquery.min.js")
      File.write(jquery, "/*! jQuery v3.7.1 | (c) OpenJS Foundation */\n!function(){}")
      plugin = File.join(dir, "jquery.timeago.js")
      File.write(plugin, "/**\n * Timeago is a jQuery plugin\n * @version 1.6.7\n * @requires jQuery v1.2.3+\n */")

      expect(inventory.scan_javascript(jquery).map { |js| [js["name"], js["version"]] }).to eq [["jquery", "3.7.1"]]
      expect(inventory.scan_javascript(plugin).map { |js| [js["name"], js["version"]] }).to eq [["timeago", "1.6.7"]]
    end
  end

  it "turns a GitHub ssh remote into a public https url, without credentials" do
    expect(inventory.public_remote("git@github.com:owner/plugin.git")).to eq "https://github.com/owner/plugin.git"
    expect(inventory.public_remote("https://user:secret@example.org/plugin.git")).to eq "https://example.org/plugin.git"
    expect(inventory.public_remote("/srv/git/plugin.git")).to be_nil
  end

  it "counts local commits on top of an upstream commit, only when the checkout contains it" do
    Dir.mktmpdir do |dir|
      git = ->(*args) { system("git", "-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.org", *args, exception: true, out: File::NULL, err: File::NULL) }
      git.call("init", "-q")
      git.call("commit", "-q", "--allow-empty", "-m", "upstream")
      upstream = `git -C #{dir} rev-parse HEAD`.strip
      git.call("commit", "-q", "--allow-empty", "-m", "local patch")
      git.call("checkout", "-q", "-b", "other", upstream)
      git.call("commit", "-q", "--allow-empty", "-m", "newer upstream")
      newer = `git -C #{dir} rev-parse HEAD`.strip
      git.call("checkout", "-q", "-")

      expect(inventory.commits_ahead(dir, upstream)).to eq 1
      expect(inventory.commits_ahead(dir, newer)).to be_nil
      expect(inventory.commits_ahead(dir, "f" * 40)).to be_nil
    end
  end
end

describe RedmineStronger::DependencyAudit::Http do
  let(:http) { described_class.new(retry_delay: 0) }
  let(:transient) { RedmineStronger::DependencyAudit::Http::TransientError }

  it "retries once after a timeout or a server error" do
    calls = 0
    allow(http).to receive(:request) do
      calls += 1
      raise transient, "Net::ReadTimeout" if calls == 1

      "{}"
    end
    expect(http.get_json("https://example.org/")).to eq({})
    expect(calls).to eq 2
  end

  it "gives up after the last attempt" do
    allow(http).to receive(:request).and_raise(transient, "HTTP 503")
    expect { http.get("https://example.org/") }.to raise_error(transient, "HTTP 503")
    expect(http).to have_received(:request).twice
  end

  it "does not retry a client error" do
    allow(http).to receive(:request).and_raise(RedmineStronger::DependencyAudit::Http::Error, "HTTP 404")
    expect { http.get("https://example.org/") }.to raise_error(RedmineStronger::DependencyAudit::Http::Error)
    expect(http).to have_received(:request).once
  end
end
