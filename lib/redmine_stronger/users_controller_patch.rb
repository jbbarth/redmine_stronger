require_dependency "users_controller"

class UsersController
  before_action :remove_lock_comment, :only => :update

  def remove_lock_comment
    #user is locked
    if @user && @user.locked? &&
        #and has a comment
        @user.lock_comment.present? &&
        #and we will unlock it
        params[:user].try(:fetch, :status) == User::STATUS_ACTIVE.to_s
      @user.update_attribute(:lock_comment, nil)
    end
  end
end
