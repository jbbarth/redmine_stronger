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

  describe ".api_users" do
    it "returns only API tokens that have been used, most recently used first" do
      old   = Token.create!(user: User.find(2), action: 'api', value: 'a' * 40, last_used_at: 2.days.ago)
      recent = Token.create!(user: User.find(3), action: 'api', value: 'b' * 40, last_used_at: 1.hour.ago)
      Token.create!(user: User.find(4), action: 'api', value: 'c' * 40, last_used_at: nil)

      result = described_class.api_users.to_a

      expect(result).to include(old, recent)
      expect(result.map(&:last_used_at)).to eq(result.map(&:last_used_at).sort.reverse)
      expect(result).to all(satisfy { |t| t.action == 'api' && t.last_used_at.present? })
    end

    it "is limited to API_USERS_LIMIT records" do
      expect(described_class.api_users.size).to be <= RedmineStronger::SecurityMetrics::API_USERS_LIMIT
    end
  end

  describe ".inactive_users_count" do
    it "returns an integer" do
      expect(described_class.inactive_users_count).to be_a(Integer)
    end
  end
end
