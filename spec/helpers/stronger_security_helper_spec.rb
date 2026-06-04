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
end
