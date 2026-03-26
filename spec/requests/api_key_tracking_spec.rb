# frozen_string_literal: true

require "spec_helper"

describe "API key session tracking" do
  include ActiveSupport::Testing::TimeHelpers
  fixtures :users, :roles, :projects, :members, :member_roles, :enabled_modules

  let(:user) { User.find_by_login("admin") }

  def api_key
    Token.where(user_id: user.id, action: 'api').delete_all
    Token.create!(user: user, action: 'api').value
  end

  def api_get(key:, ip: '1.2.3.4')
    get "/projects.json",
        params: { key: key },
        env: { 'REMOTE_ADDR' => ip }
  end

  before do
    UserLoginSession.where(user_id: user.id).delete_all
    Setting.rest_api_enabled = '1'
  end

  after do
    Setting.rest_api_enabled = '0'
  end

  it "creates a UserLoginSession with auth_method 'api_key' on first request" do
    expect {
      api_get(key: api_key)
    }.to change { UserLoginSession.where(user_id: user.id, auth_method: 'api_key').count }.by(1)
  end

  it "records the correct IP address" do
    api_get(key: api_key, ip: '10.20.30.40')
    session = UserLoginSession.where(user_id: user.id, auth_method: 'api_key').last
    expect(session.ip_address).to eq('10.20.30.40')
  end

  it "does not create a second session for the same IP within 1 day" do
    key = api_key
    api_get(key: key, ip: '1.2.3.4')
    expect {
      api_get(key: key, ip: '1.2.3.4')
    }.not_to change { UserLoginSession.where(user_id: user.id, auth_method: 'api_key').count }
  end

  it "creates a new session for a different IP" do
    key = api_key
    api_get(key: key, ip: '1.2.3.4')
    expect {
      api_get(key: key, ip: '5.6.7.8')
    }.to change { UserLoginSession.where(user_id: user.id, auth_method: 'api_key').count }.by(1)
  end

  it "creates a new session for the same IP after 1 day" do
    key = api_key
    travel_to 2.days.ago do
      api_get(key: key, ip: '1.2.3.4')
    end
    expect {
      api_get(key: key, ip: '1.2.3.4')
    }.to change { UserLoginSession.where(user_id: user.id, auth_method: 'api_key').count }.by(1)
  end

  it "does not create a session without an API key" do
    expect {
      get "/projects.json"
    }.not_to change { UserLoginSession.where(user_id: user.id, auth_method: 'api_key').count }
  end

  it "does not create a session for an invalid API key" do
    expect {
      api_get(key: 'invalidkeyvalue0000000000000000000000000')
    }.not_to change { UserLoginSession.where(user_id: user.id, auth_method: 'api_key').count }
  end
end
