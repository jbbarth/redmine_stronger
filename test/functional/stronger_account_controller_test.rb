require File.expand_path("../../test_helper", __FILE__)
require "account_controller"

class StrongerAccountControllerTest < ActionController::TestCase
  fixtures :users, :roles

  setup do
    @controller = AccountController.new
    @request    = ActionController::TestRequest.new
    @response   = ActionController::TestResponse.new
    @max_failed_attempts = AccountController::MAX_FAILED_ATTEMPTS
    User.current = nil
  end

  teardown do
    User.find_by_login("admin").activate!
  end

  test "lock account after 3 failed attempts" do
    user = User.find_by_login("admin")
    @max_failed_attempts.times do
      assert !user.reload.locked?, "User shouldn't be locked"
      post :login, :username => "admin", :password => "bad"
      assert_response :success
      assert_template "login"
    end
    assert user.reload.locked?, "User should be locked"
  end

  test "reset counters with successful login" do
    user = User.find_by_login("admin")
    1.times do
      post :login, :username => "admin", :password => "bad"
    end
    post :login, :username => "admin", :password => "admin"
    assert_equal 0, user.reload.pref[:brute_force_counter]
  end
end
