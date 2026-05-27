require_relative "brute_force"

module RedmineStronger
  module AccountControllerPatch

    # Patch #invalid_credentials to feed the shared brute-force counter.
    def invalid_credentials
      BruteForce.register_failure(params[:username])
      # original action
      super

      flash.now[:error] = l(:notice_account_invalid_credentials_or_locked) unless Rails.env == 'test'
    end

    def account_locked(user, redirect_path=signin_path)
      if BruteForce.lock_time(user)&.past?
        # reactivate user when lock time is past
        BruteForce.unlock(user)
        successful_authentication(user)
      else
        flash[:error] = l(:notice_account_invalid_credentials_or_locked)
        redirect_to redirect_path
      end
    end

    # Patch #successful_authentication to reset the shared brute-force counter.
    def successful_authentication(user)
      BruteForce.reset(user)
      super
    end
  end
end

AccountController.prepend RedmineStronger::AccountControllerPatch
