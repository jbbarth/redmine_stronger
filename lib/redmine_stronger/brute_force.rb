# frozen_string_literal: true

module RedmineStronger

  module BruteForce
    # Maximum number of failed attempts before locking the account.
    MAX_FAILED_ATTEMPTS = 5
    # Duration of the temporary lock, in minutes.
    LOCKED_FOR_MINUTES = 20

    module_function

    # Records a failed authentication attempt for the given login.
    def register_failure(login)
      user = User.active.find_by_login(login.to_s)
      return unless user

      set_counter(user, counter(user) + 1)
      lock!(user) if counter(user) >= MAX_FAILED_ATTEMPTS
    end

    # Resets the failure counter after a successful authentication.
    def reset(user)
      return unless user

      set_counter(user, 0)
    end

    # Reactivates a brute-force-locked account whose lock duration has expired.
    def unlock_if_expired(login)
      user = User.find_by_login(login.to_s)
      return unless user&.locked? && lock_time(user)&.past?

      unlock(user)
    end

    # Clears the temporary lock and reactivates the account.
    def unlock(user)
      user.update_attribute(:lock_comment, nil)
      user.activate!
      set_lock_time(user, nil)
    end

    def lock_time(user)
      user.pref[:brute_force_lock_time]
    end

    def counter(user)
      user.pref[:brute_force_counter].to_i
    end

    def lock!(user)
      set_lock_time(user, Time.now + LOCKED_FOR_MINUTES.minutes)
      user.update_attribute(
        :lock_comment,
        "Locked at #{Time.now} after #{MAX_FAILED_ATTEMPTS} erroneous password"
      )
      user.lock!
    end

    def set_counter(user, value)
      pref = user.pref
      pref[:brute_force_counter] = value
      pref.save
    end

    def set_lock_time(user, time)
      pref = user.pref
      pref[:brute_force_lock_time] = time
      pref.save
    end
  end
end
