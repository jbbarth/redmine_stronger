# frozen_string_literal: true

require "spec_helper"

describe StrongerSecurityHelper, type: :helper do
  fixtures :users

  describe "#stronger_admin_badge" do
    it "returns a badge for an admin user" do
      badge = helper.stronger_admin_badge(User.find_by_login("admin"))
      expect(badge).to include("stronger-admin-badge")
      expect(badge).to include(I18n.t(:stronger_admin_badge))
    end

    it "returns a badge for a sudoer who is not currently admin" do
      user = User.find_by_login("jsmith")
      user.update_column(:admin, false)
      user.update_column(:sudoer, true) if user.respond_to?(:sudoer)

      expect(helper.stronger_admin_badge(user)).to include("stronger-admin-badge")
    end

    it "returns nil for a regular user" do
      user = User.find_by_login("jsmith")
      user.update_column(:admin, false)
      user.update_column(:sudoer, false) if user.respond_to?(:sudoer)

      expect(helper.stronger_admin_badge(user)).to be_nil
    end

    it "returns nil for a nil user" do
      expect(helper.stronger_admin_badge(nil)).to be_nil
    end
  end
end
