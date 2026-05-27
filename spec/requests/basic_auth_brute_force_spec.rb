# frozen_string_literal: true

require "spec_helper"

# Anti-brute-force mechanism must cover the API HTTP Basic authentication, not only the web login form.
describe "API HTTP Basic auth brute-force protection" do
  include ActiveSupport::Testing::TimeHelpers
  fixtures :users, :roles, :projects, :members, :member_roles, :enabled_modules

  let(:user) { User.find_by_login("jsmith") }

  def basic_header(login, password)
    { "Authorization" => ActionController::HttpAuthentication::Basic.encode_credentials(login, password) }
  end

  def api_get(login:, password:)
    get "/users/current.json", headers: basic_header(login, password)
  end

  def reset_brute_force!(login)
    u = User.find_by_login(login)
    u.activate! if u.locked?
    u.pref[:brute_force_counter] = 0
    u.pref[:brute_force_lock_time] = nil
    u.pref.save
  end

  before do
    Setting.rest_api_enabled = "1"
    reset_brute_force!("jsmith")
  end

  after do
    reset_brute_force!("jsmith")
    Setting.rest_api_enabled = "0"
    travel_back
  end

  it "increments the brute-force counter on a failed Basic auth attempt" do
    api_get(login: "jsmith", password: "wrong")
    expect(response).to have_http_status(:unauthorized)
    expect(user.reload.pref[:brute_force_counter]).to eq 1
  end

  it "locks the account after MAX_FAILED_ATTEMPTS failed attempts over the API" do
    RedmineStronger::BruteForce::MAX_FAILED_ATTEMPTS.times do
      api_get(login: "jsmith", password: "wrong")
    end
    user.reload
    expect(user.locked?).to be_truthy
    expect(user.lock_comment).to match(/Locked at/)
  end

  it "denies access even with the correct password once locked" do
    RedmineStronger::BruteForce::MAX_FAILED_ATTEMPTS.times do
      api_get(login: "jsmith", password: "wrong")
    end
    api_get(login: "jsmith", password: "jsmith")
    expect(response).to have_http_status(:unauthorized)
  end

  it "resets the counter on a successful Basic auth" do
    api_get(login: "jsmith", password: "wrong")
    expect(user.reload.pref[:brute_force_counter]).to eq 1

    api_get(login: "jsmith", password: "jsmith")
    expect(response).to be_successful
    expect(user.reload.pref[:brute_force_counter]).to eq 0
  end

  it "auto-unlocks after the lock period and allows login with the correct password" do
    RedmineStronger::BruteForce::MAX_FAILED_ATTEMPTS.times do
      api_get(login: "jsmith", password: "wrong")
    end
    expect(user.reload.locked?).to be_truthy

    travel_to RedmineStronger::BruteForce::LOCKED_FOR_MINUTES.minutes.from_now + 1.second
    api_get(login: "jsmith", password: "jsmith")
    expect(response).to be_successful
    user.reload
    expect(user.active?).to be_truthy
    expect(user.pref[:brute_force_lock_time]).to be_nil
  end

  it "does not raise nor count failures for an unknown login" do
    expect {
      api_get(login: "does-not-exist", password: "whatever")
    }.not_to raise_error
    expect(response).to have_http_status(:unauthorized)
  end
end
