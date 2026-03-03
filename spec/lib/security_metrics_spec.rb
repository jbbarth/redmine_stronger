# frozen_string_literal: true

require "spec_helper"

describe RedmineStronger::SecurityMetrics do
  fixtures :users, :roles, :projects, :members, :member_roles,
           :issues, :issue_statuses, :trackers, :enabled_modules

  describe ".inactive_users" do
    it "returns active users who haven't logged in recently" do
      inactive = described_class.inactive_users
      inactive.each do |user|
        expect(user.active?).to be true
        if user.last_login_on
          expect(user.last_login_on).to be < RedmineStronger::SecurityMetrics::INACTIVE_DAYS.days.ago
        end
      end
    end

    it "is limited to INACTIVE_USERS_LIMIT records" do
      expect(described_class.inactive_users.size).to be <= RedmineStronger::SecurityMetrics::INACTIVE_USERS_LIMIT
    end
  end

  describe ".users_without_2fa" do
    it "returns active users with no twofa_scheme" do
      users = described_class.users_without_2fa
      users.each do |user|
        expect(user.active?).to be true
        expect(user.twofa_scheme).to be_nil
      end
    end
  end

  describe ".inactive_users_count" do
    it "returns an integer" do
      expect(described_class.inactive_users_count).to be_a(Integer)
    end
  end
end
