require "spec_helper"

describe "users" do
  fixtures :users

  #taken from core
  def log_user(login, password)
    User.anonymous
    get "/login"
    assert_equal nil, session[:user_id]
    assert_response :success
    assert_template "account/login"
    post "/login", params: {:username => login, :password => password}
    assert_equal login, User.find(session[:user_id]).login
  end

  describe "removes lock comment" do
    let(:user) { User.find(2) }

    before do
      user.lock!
      user.update_attribute(:lock_comment, "account locked")
      log_user("admin", "admin")
    end

    it "removes lock_comment when unlocking a user" do
      put user_path(user.id, :user => {:status => User::STATUS_ACTIVE})
      expect(user.reload.lock_comment).to be_blank
    end

    it "keeps lock_comment when updating without unlocking" do
      put user_path(user.id, :mail => "blah@foo.net")
      expect(user.reload.lock_comment).to_not be_blank
    end
  end
end
