# frozen_string_literal: true

class UserLoginSession < ActiveRecord::Base
  belongs_to :user

  MAX_SESSIONS_PER_USER = 20
  RECENT_DAYS = 7
  RECENT_LIMIT = 5

  # Returns sessions to display for a user:
  # all sessions from the last 7 days, plus at least the 5 most recent
  # (in case the user hasn't logged in for more than 7 days).
  def self.for_display(user)
    recent_ids = where(user_id: user.id)
                   .where('logged_in_at >= ?', RECENT_DAYS.days.ago)
                   .order(logged_in_at: :desc)
                   .pluck(:id)
    last_n_ids = where(user_id: user.id)
                   .order(logged_in_at: :desc)
                   .limit(RECENT_LIMIT)
                   .pluck(:id)
    ids = (recent_ids + last_n_ids).uniq
    where(id: ids).order(logged_in_at: :desc)
  end

  # Parses the OS name from a User-Agent string.
  def self.parse_os(ua)
    ua = ua.to_s
    if ua =~ /Android/
      'Android'
    elsif ua =~ /iPhone|iPod/
      'iOS'
    elsif ua =~ /iPad/
      'iPadOS'
    elsif ua =~ /Windows NT/
      'Windows'
    elsif ua =~ /Mac OS X/
      'macOS'
    elsif ua =~ /CrOS/
      'Chrome OS'
    elsif ua =~ /Linux/
      'Linux'
    else
      'Unknown'
    end
  end

  # Parses the device type from a User-Agent string.
  def self.parse_device_type(ua)
    ua = ua.to_s
    if ua =~ /iPad/i || (ua =~ /tablet/i && ua !~ /Mobile/i)
      'tablet'
    elsif ua =~ /Mobile|Android|iPhone|iPod/i
      'mobile'
    else
      'desktop'
    end
  end

  def mobile?
    device_type == 'mobile'
  end

  def tablet?
    device_type == 'tablet'
  end

  def desktop?
    device_type == 'desktop'
  end
end
