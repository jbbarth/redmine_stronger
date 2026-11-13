# frozen_string_literal: true

require "spec_helper"

describe RedmineStronger::DependencyAudit::Collector do
  let(:inventory) do
    instance_double(
      RedmineStronger::DependencyAudit::Inventory,
      environment: [{ "kind" => "os", "name" => "Debian 11", "product" => "debian", "version" => "11", "codename" => "bullseye" }],
      gems: [{ "kind" => "gem", "name" => "rack", "version" => "3.2.6", "rubygems" => true }],
      packages: [{ "kind" => "package", "name" => "libxml2", "version" => "2.9.10", "key" => true },
                 { "kind" => "package", "name" => "libfoo", "version" => "1.0", "key" => false }],
      javascripts: [], plugins: []
    )
  end

  let(:advisory_db) do
    instance_double(RedmineStronger::DependencyAudit::AdvisoryDb,
                    for_gem: [{ "id" => "CVE-2026-0001", "severity" => "high" }], for_ruby: [])
  end

  let(:failing_http) do
    double("http").tap do |http|
      allow(http).to receive(:get).and_raise(RedmineStronger::DependencyAudit::Http::Error, "HTTP 503")
      allow(http).to receive(:get_json).and_raise(RedmineStronger::DependencyAudit::Http::Error, "HTTP 503")
    end
  end

  it "keeps the other sources when one fails" do
    collector = described_class.new(http: failing_http, inventory: inventory, advisory_db: advisory_db,
                                    sources: %w(advisories endoflife debian))
    payload = collector.run

    expect(payload["gems"].first["advisories"].first["id"]).to eq "CVE-2026-0001"
    expect(payload["errors"].pluck("source")).to include("endoflife", "debian")
    expect(described_class.alert_count(payload)).to eq 1
  end

  it "reports a release no longer followed by the Debian security team" do
    tracker = RedmineStronger::DependencyAudit::Sources::DebianTracker.new(
      "openssl" => { "CVE-2026-0002" => { "releases" => { "bookworm" => {} } } }
    )
    collector = described_class.new(http: failing_http, inventory: inventory, debian_tracker: tracker, sources: %w(debian))
    payload = collector.run

    expect(payload["package_tracking"]).to eq "untracked"
    expect(payload["packages"].pluck("name")).to eq ["libxml2"]
    expect(payload["packages_total"]).to eq 2
  end

  it "keeps only actionable advisories outside key packages" do
    tracker = RedmineStronger::DependencyAudit::Sources::DebianTracker.new(
      "openssl" => { "CVE-0" => { "releases" => { "bullseye" => {} } } },
      "libxml2" => { "CVE-1" => { "releases" => { "bullseye" => { "status" => "open", "urgency" => "medium" } } },
                     "CVE-2" => { "releases" => { "bullseye" => { "status" => "open", "urgency" => "unimportant" } } } },
      "libfoo" => { "CVE-3" => { "releases" => { "bullseye" => { "status" => "open", "urgency" => "high" } } },
                    "CVE-4" => { "releases" => { "bullseye" => { "status" => "resolved", "fixed_version" => "1.1", "urgency" => "low" } } } }
    )
    payload = described_class.new(http: failing_http, inventory: inventory, debian_tracker: tracker, sources: %w(debian)).run

    advisories = payload["packages"].to_h { |p| [p["name"], p["advisories"].pluck("id")] }
    expect(advisories).to eq("libxml2" => ["CVE-1"], "libfoo" => ["CVE-4"])
  end

  it "only reads the local inventory when offline" do
    payload = described_class.new(http: failing_http, inventory: inventory, offline: true).run

    expect(payload["sources"]).to be_empty
    expect(payload["errors"]).to be_empty
    expect(payload["gems"].first).not_to have_key("advisories")
  end
end
