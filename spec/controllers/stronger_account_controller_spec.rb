require "spec_helper"
require "account_controller"

describe AccountController do
  fixtures :users, :roles
  include ActiveSupport::Testing::TimeHelpers

  before do
    @max_failed_attempts = AccountController::MAX_FAILED_ATTEMPTS
    @lock_time = AccountController::LOCKED_FOR_MINUTES

    User.current = nil
  end

  teardown do
    User.find_by_login("admin").activate!
    travel_back
  end

  it "should lock account after 5 failed attempts" do
    user = User.find_by_login("admin")
    @max_failed_attempts.times do
      assert !user.reload.locked?, "User shouldn't be locked"
      post :login, params: {:username => "admin", :password => "bad"}
      expect(response).to be_successful
      assert_template "login"
    end
    user.reload
    assert user.locked?, "User should be locked"
    assert user.lock_comment.match /Locked at/
  end

  it "should reset counters with successful login" do
    user = User.find_by_login("admin")
    1.times do
      post :login, params: {:username => "admin", :password => "bad"}
    end
    post :login, params: {:username => "admin", :password => "admin"}
    expect(user.reload.pref[:brute_force_counter]).to eq 0
  end

  it "should automatically unlock account on login after #{@lock_time} minutes" do
    user = User.find_by_login("admin")
    @max_failed_attempts.times do
      post :login, params: {:username => "admin", :password => "bad"}
      expect(response).to be_successful
    end
    expect(user.reload.locked?).to be_truthy
    expect(user.pref[:brute_force_lock_time]).to be_present

    travel_to @lock_time.minutes.from_now + 1.second
    post :login, params: {:username => "admin", :password => "admin"}
    expect(user.reload.active?).to be_truthy
    expect(user.pref[:brute_force_lock_time]).to be_nil
  end
end
