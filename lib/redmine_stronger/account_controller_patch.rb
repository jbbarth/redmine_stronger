require_dependency "account_controller"

class AccountController
  # Maximum number of failed attempts before locking
  MAX_FAILED_ATTEMPTS = 5

  # Patch #invalid_credentials to add a brute force attack counter
  #
  # The counter increments each time the user logs in with a bad password. When
  # the counter reaches the max failed attemps limit, it locks the account.
  def invalid_credentials_with_locking
    if user = User.active.find_by_login(params[:username].to_s)
      #increment brute-force counter
      set_brute_force_counter(user, get_brute_force_counter(user) + 1)
      #lock the user immediately if detecting a brute force attack
      if brute_forcing?(user)
        user.update_attribute(:lock_comment, "Locked at #{Time.now} after #{MAX_FAILED_ATTEMPTS} erroneous password")
        user.lock!
      end
    end
    #original action
    invalid_credentials_without_locking
  end
  alias_method_chain :invalid_credentials, :locking

  # Patch #successful_authentication to reset brute force attack counter
  #
  # On successful authentication, brute_force_counter should be reset to 0 so
  # that user won't have problems the next time he mistakenly fills his
  # password.
  def successful_authentication_with_locking(user)
    set_brute_force_counter(user, 0)
    successful_authentication_without_locking(user)
  end
  alias_method_chain :successful_authentication, :locking

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
end
