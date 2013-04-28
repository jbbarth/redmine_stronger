require File.expand_path("../../test_helper", __FILE__)
require "account_controller"

class StrongerAccountControllerTest < ActionController::TestCase
  fixtures :users, :roles

  setup do
    @controller = AccountController.new
    @request    = ActionController::TestRequest.new
    @response   = ActionController::TestResponse.new
    User.current = nil
  end

  teardown do
    User.find_by_login("admin").activate!
  end

  test "lock account after 3 failed attempts" do
    user = User.find_by_login("admin")
    3.times do
      assert !user.reload.locked?, "User shouldn't be locked"
      post :login, :username => "admin", :password => "bad"
      assert_response :success
      assert_template "login"
    end
    assert user.reload.locked?, "User should be locked"
  end
end
