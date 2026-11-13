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
end
