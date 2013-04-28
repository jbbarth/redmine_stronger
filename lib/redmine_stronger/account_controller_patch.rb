require_dependency "account_controller"

class AccountController
  def invalid_credentials_with_locking
    if user = User.active.find_by_login(params[:username].to_s)
      #increment brute-force counter
      set_brute_force_counter(user, get_brute_force_counter(user) + 1)
      #lock the user immediately if detecting a brute force attack
      user.lock! if brute_forcing?(user)
    end
    #original action
    invalid_credentials_without_locking
  end
  alias_method_chain :invalid_credentials, :locking

  def successful_authentication_with_locking(user)
    set_brute_force_counter(user, 0)
    successful_authentication_without_locking(user)
  end
  alias_method_chain :successful_authentication, :locking


  private
  def brute_forcing?(user)
    user.pref[:brute_force_counter].to_i >= 3
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
