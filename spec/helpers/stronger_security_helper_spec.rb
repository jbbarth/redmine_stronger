# frozen_string_literal: true

require "spec_helper"

describe StrongerSecurityHelper, type: :helper do
  describe "#stronger_admin_badge" do
    it "returns a badge for an admin user" do
      badge = helper.stronger_admin_badge(User.new(admin: true))
      expect(badge).to include("stronger-admin-badge")
      expect(badge).to include(I18n.t(:stronger_admin_badge))
    end

    it "returns a badge for a sudoer who is not currently admin" do
      skip "redmine_sudo not installed" unless User.new.respond_to?(:sudoer=)

      user = User.new(admin: false)
      user.sudoer = true

      expect(helper.stronger_admin_badge(user)).to include("stronger-admin-badge")
    end

    it "returns nil for a regular non-admin user" do
      expect(helper.stronger_admin_badge(User.new(admin: false))).to be_nil
    end

    it "returns nil for a nil user" do
      expect(helper.stronger_admin_badge(nil)).to be_nil
    end
  end

  describe "#stronger_item_status" do
    it "does not flag the latest release of a branch that only gets security fixes" do
      rails = { "kind" => "rails", "version" => "8.1.4.1", "branch_latest" => "8.1.4.1", "latest" => "8.1.4.1",
                "security_only" => true }
      expect(helper.stronger_item_status(rails)).to eq "ok"
    end

    it "flags a newer release in the branch" do
      expect(helper.stronger_item_status("version" => "17.11", "branch_latest" => "17.12")).to eq "outdated"
    end

    it "flags a high vulnerability before anything else" do
      item = { "version" => "3.2.6", "branch_latest" => "3.2.8", "advisories" => [{ "severity" => "high" }] }
      expect(helper.stronger_item_status(item)).to eq "alert"
    end
  end

  describe "#stronger_new_issue_link" do
    let(:report) do
      environment = [{ "name" => "Debian GNU/Linux 12 (bookworm)", "version" => "12" },
                     { "name" => "Redmine", "version" => "7.0.3" }]
      StrongerDependencyReport.new(collected_at: Time.zone.parse("2026-11-13 08:00"),
                                   data: JSON.generate("environment" => environment))
    end
    let(:gem) do
      { "kind" => "gem", "name" => "rack", "version" => "3.2.6", "branch_latest" => "3.2.7", "latest" => "3.3.0",
        "advisories" => [{ "id" => "CVE-2026-0002", "severity" => "medium", "fixed" => [">= 3.2.7"],
                           "url" => "https://example.org/CVE-2026-0002" },
                         { "id" => "CVE-2026-0001", "severity" => "high", "fixed" => [], "url" => "javascript:x" }] }
    end

    before { I18n.locale = :en }
    after { I18n.locale = :en }

    it "is only offered for items needing an action" do
      expect(helper.stronger_new_issue_link(gem.merge("advisories" => [], "branch_latest" => "3.2.6",
                                                      "latest" => "3.2.6"), report)).to be_nil
      expect(helper.stronger_new_issue_link(gem, report)).to include("/issues/new?issue")
    end

    it "names the component, the versions and the number of vulnerabilities in the subject" do
      expect(helper.stronger_issue_subject(gem)).to eq "Update rack (gem) from 3.2.6 to 3.2.7: 2 known vulnerabilities"
    end

    it "moves an end of life component to the latest release, not to the end of its branch" do
      ruby = { "kind" => "ruby", "name" => "Ruby", "version" => "3.1.4", "branch_latest" => "3.1.7",
               "latest" => "4.0.9", "eol" => true, "advisories" => [] }
      expect(helper.stronger_issue_subject(ruby)).to eq "Update Ruby from 3.1.4 to 4.0.9: End of life"
    end

    it "lists the vulnerabilities most severe first, with http links only" do
      description = helper.stronger_issue_description(gem, report)
      expect(description.index("CVE-2026-0001")).to be < description.index("CVE-2026-0002")
      expect(description).to include("Fixed in >= 3.2.7. https://example.org/CVE-2026-0002")
      expect(description).not_to include("javascript:")
      expect(description).to include(stronger_security_dependencies_url)
    end

    it "gives the maintainer the dependency type and an indicative command" do
      description = helper.stronger_issue_description(gem.merge("direct" => false), report)
      expect(description).to include("indirect (required by another gem)", "bundle update --conservative rack",
                                     "Environment: Debian GNU/Linux 12 (bookworm), Redmine 7.0.3")
    end
  end

  describe "#stronger_overview_tiles" do
    let(:clean) do
      { anon: 0, anon_open: 0, non_member: 0, non_member_open: 0, wikis: 0, wiki_projects: 4,
        inactive: 0, inactive_admins: 0, locked: 0, api: 3 }
    end

    def statuses(counts)
      helper.stronger_overview_tiles(**counts).to_h { |tile| [tile[:anchor], tile[:status]] }
    end

    it "shows a clean instance in green, API accounts being informative only" do
      expect(statuses(clean)).to eq("stronger-anon" => "ok", "stronger-non-member" => "ok", "stronger-wikis" => "ok",
                                    "stronger-inactive" => "ok", "stronger-locked" => "ok",
                                    "stronger-api" => "unknown")
    end

    it "raises an alert for issues visible without login and for inactive administrators" do
      tiles = statuses(clean.merge(anon: 5, anon_open: 2, inactive: 10, inactive_admins: 1))
      expect(tiles).to include("stronger-anon" => "alert", "stronger-inactive" => "alert")
    end

    it "asks for a review of the other findings" do
      tiles = statuses(clean.merge(non_member: 3, non_member_open: 1, wikis: 2, inactive: 4, locked: 1))
      expect(tiles).to include("stronger-non-member" => "vulnerable", "stronger-wikis" => "vulnerable",
                               "stronger-inactive" => "outdated", "stronger-locked" => "outdated")
    end

    it "adds the documentation tile only when redmine_second_wiki provides it" do
      expect(statuses(clean)).not_to have_key("stronger-documentations")
      expect(statuses(clean.merge(documentations: 1, documentation_projects: 2)))
        .to include("stronger-documentations" => "vulnerable")
    end
  end
end
