# frozen_string_literal: true

require "spec_helper"

describe RedmineStronger::DependencyAudit::DebianVersion do
  {
    ["1:2.0", "2.9"] => 1,
    ["1.0~rc1", "1.0"] => -1,
    ["1.0", "1.0+deb12u1"] => -1,
    ["2.9.14+dfsg-1.3~deb12u4", "2.9.14+dfsg-1.3~deb12u1"] => 1,
    ["2.9.14+dfsg-1.3~deb12u1", "2.9.14+dfsg-1.3"] => -1,
    ["1.0-1", "1.0-1"] => 0,
    ["1.10", "1.9"] => 1,
    ["1.0a", "1.0+"] => -1
  }.each do |(a, b), expected|
    it "compares #{a} and #{b} like dpkg" do
      expect(described_class.compare(a, b)).to eq expected
    end
  end
end

describe RedmineStronger::DependencyAudit::Sources::DebianTracker do
  let(:tracker) do
    described_class.new(
      "libxml2" => {
        "CVE-2026-0001" => { "description" => "fixed", "releases" => {
          "bookworm" => { "status" => "resolved", "fixed_version" => "2.9.14+dfsg-1.3~deb12u5", "urgency" => "high" }
        } },
        "CVE-2026-0002" => { "description" => "open", "releases" => {
          "bookworm" => { "status" => "open", "urgency" => "low" }
        } },
        "CVE-2026-0003" => { "description" => "not affected", "releases" => {
          "bookworm" => { "status" => "resolved", "fixed_version" => "0", "urgency" => "unimportant" }
        } }
      },
      "openssl" => { "CVE-2026-0004" => { "releases" => { "bookworm" => {}, "trixie" => {} } } }
    )
  end

  it "knows which releases are still tracked" do
    expect(tracker.tracked?("bookworm")).to be true
    expect(tracker.tracked?("bullseye")).to be false
  end

  it "reports fixes newer than the installed version and open issues" do
    advisories = tracker.advisories("libxml2", "2.9.14+dfsg-1.3~deb12u4", "bookworm")
    expect(advisories.map { |a| [a["id"], a["fix_available"], a["severity"]] })
      .to contain_exactly(["CVE-2026-0001", true, "high"], ["CVE-2026-0002", false, "low"])
  end

  it "drops fixes already installed" do
    advisories = tracker.advisories("libxml2", "2.9.14+dfsg-1.3~deb12u5", "bookworm")
    expect(advisories.pluck("id")).to eq ["CVE-2026-0002"]
  end
end
