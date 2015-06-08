require "spec_helper"
require "account_controller"

describe AccountController do
  fixtures :users, :roles

  before do
    @max_failed_attempts = AccountController::MAX_FAILED_ATTEMPTS
    User.current = nil
  end

  teardown do
    User.find_by_login("admin").activate!
  end

  it "should lock account after 3 failed attempts" do
    user = User.find_by_login("admin")
    @max_failed_attempts.times do
      assert !user.reload.locked?, "User shouldn't be locked"
      post :login, :username => "admin", :password => "bad"
      expect(response).to be_success
      assert_template "login"
    end
    user.reload
    assert user.locked?, "User should be locked"
    assert user.lock_comment.match /Locked at/
  end

  it "should reset counters with successful login" do
    user = User.find_by_login("admin")
    1.times do
      post :login, :username => "admin", :password => "bad"
    end
    post :login, :username => "admin", :password => "admin"
    user.reload.pref[:brute_force_counter].should == 0
  end
end
