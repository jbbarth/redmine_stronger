# frozen_string_literal: true

require "spec_helper"

describe UserLoginSession do
  fixtures :users

  describe ".parse_os" do
    {
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit..."  => "Windows",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)..."        => "macOS",
      "Mozilla/5.0 (X11; Linux x86_64)..."                        => "Linux",
      "Mozilla/5.0 (X11; CrOS x86_64 14526.89.0)..."             => "Chrome OS",
      "Mozilla/5.0 (Linux; Android 12; Pixel 6)..."               => "Android",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)..." => "iOS",
      "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X)..."          => "iPadOS",
      ""                                                           => "Unknown",
    }.each do |ua, expected_os|
      it "detects '#{expected_os}' from user-agent" do
        expect(described_class.parse_os(ua)).to eq(expected_os)
      end
    end
  end

  describe ".parse_device_type" do
    {
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."              => "desktop",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X)..."                 => "desktop",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)..." => "mobile",
      "Mozilla/5.0 (Linux; Android 12; Pixel 6) Mobile..."        => "mobile",
      "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X)..."          => "tablet",
      "Mozilla/5.0 (Linux; Android 4.4.2; Tablet Build/KOT49H)..." => "tablet",
      ""                                                           => "desktop",
    }.each do |ua, expected_type|
      it "detects '#{expected_type}' from user-agent" do
        expect(described_class.parse_device_type(ua)).to eq(expected_type)
      end
    end
  end

  describe ".for_display" do
    let(:user) { User.find_by_login("admin") }

    before do
      UserLoginSession.where(user_id: user.id).delete_all
    end

    it "returns last 5 sessions when all are older than 7 days" do
      10.times do |i|
        UserLoginSession.create!(
          user: user,
          logged_in_at: (10 + i).days.ago,
          ip_address: "1.2.3.#{i}",
          auth_method: "password",
          os: "Linux",
          device_type: "desktop"
        )
      end

      expect(described_class.for_display(user).count).to eq(5)
    end

    it "returns all sessions from the last 7 days" do
      # Create 6 sessions clearly within the 7-day window
      6.times do |i|
        UserLoginSession.create!(
          user: user,
          logged_in_at: (i + 1).days.ago,
          ip_address: "1.2.3.#{i}",
          auth_method: "password",
          os: "Linux",
          device_type: "desktop"
        )
      end

      expect(described_class.for_display(user).count).to eq(6)
    end

    it "merges recent + last 5 when some sessions are older than 7 days" do
      # 3 sessions in last 7 days
      3.times do |i|
        UserLoginSession.create!(
          user: user,
          logged_in_at: (i + 1).days.ago,
          ip_address: "1.2.3.#{i}",
          auth_method: "password",
          os: "Linux",
          device_type: "desktop"
        )
      end
      # 4 sessions older than 7 days
      4.times do |i|
        UserLoginSession.create!(
          user: user,
          logged_in_at: (10 + i).days.ago,
          ip_address: "10.0.0.#{i}",
          auth_method: "cas",
          os: "Windows",
          device_type: "desktop"
        )
      end

      # Should show 3 recent + 2 more to reach 5 total
      expect(described_class.for_display(user).count).to eq(5)
    end

    it "returns results ordered by most recent first" do
      3.times do |i|
        UserLoginSession.create!(
          user: user,
          logged_in_at: (i + 1).days.ago,
          ip_address: "1.2.3.#{i}",
          auth_method: "password",
          os: "Linux",
          device_type: "desktop"
        )
      end

      sessions = described_class.for_display(user)
      expect(sessions.first.logged_in_at).to be > sessions.last.logged_in_at
    end
  end

  describe "#mobile? / #tablet? / #desktop?" do
    it "returns true for mobile device" do
      s = UserLoginSession.new(device_type: "mobile")
      expect(s.mobile?).to be true
      expect(s.tablet?).to be false
      expect(s.desktop?).to be false
    end

    it "returns true for tablet device" do
      s = UserLoginSession.new(device_type: "tablet")
      expect(s.mobile?).to be false
      expect(s.tablet?).to be true
      expect(s.desktop?).to be false
    end

    it "returns true for desktop device" do
      s = UserLoginSession.new(device_type: "desktop")
      expect(s.mobile?).to be false
      expect(s.tablet?).to be false
      expect(s.desktop?).to be true
    end
  end
end
