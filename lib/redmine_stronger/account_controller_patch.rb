require_dependency "account_controller"

module PluginStronger
  module AccountController

    # Maximum number of failed attempts before locking
    MAX_FAILED_ATTEMPTS = 5
    LOCKED_FOR_MINUTES = 20

    # Patch #invalid_credentials to add a brute force attack counter
    #
    # The counter increments each time the user logs in with a bad password. When
    # the counter reaches the max failed attemps limit, it locks the account.
    def invalid_credentials
      if user = User.active.find_by_login(params[:username].to_s)
        #increment brute-force counter
        set_brute_force_counter(user, get_brute_force_counter(user) + 1)
        #lock the user immediately if detecting a brute force attack
        if brute_forcing?(user)
          set_brute_force_lock_time(user, Time.now + LOCKED_FOR_MINUTES.minutes)
          user.update_attribute(:lock_comment, "Locked at #{Time.now} after #{MAX_FAILED_ATTEMPTS} erroneous password")
          user.lock!
        end
      end
      # original action
      super
      
      flash.now[:error] = l(:notice_account_invalid_credentials_or_locked) unless Rails.env == 'test'
    end

    def account_locked(user, redirect_path=signin_path)
      if get_brute_force_lock_time(user)&.past?
        # reactivate user when lock time is past
        user.update_attribute(:lock_comment, nil)
        user.activate!
        set_brute_force_lock_time(user, nil)
        successful_authentication(user)
      else
        flash[:error] = l(:notice_account_invalid_credentials_or_locked)
        redirect_to redirect_path
      end
    end
    # Patch #successful_authentication to reset brute force attack counter
    #
    # On successful authentication, brute_force_counter should be reset to 0 so
    # that user won't have problems the next time he mistakenly fills his
    # password.
    def successful_authentication(user)
      set_brute_force_counter(user, 0)
      super
    end

    private

    def brute_forcing?(user)
      user.pref[:brute_force_counter].to_i >= MAX_FAILED_ATTEMPTS
    end

    def set_brute_force_counter(user, value)
      pref = user.pref
      pref[:brute_force_counter] = value
      pref.save
    end

    def get_brute_force_counter(user)
      user.pref[:brute_force_counter].to_i
    end

    def set_brute_force_lock_time(user, time)
      pref = user.pref
      pref[:brute_force_lock_time] = time
      pref.save
    end

    def get_brute_force_lock_time(user)
      user.pref[:brute_force_lock_time]
    end
  end
end

AccountController.prepend PluginStronger::AccountController
