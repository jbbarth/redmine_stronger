# frozen_string_literal: true

require "spec_helper"

describe "Intranet-only API restriction" do
  fixtures :users, :roles, :projects, :members, :member_roles, :enabled_modules

  let(:user) { User.find_by_login("admin") }

  def api_key
    Token.where(user_id: user.id, action: 'api').delete_all
    Token.create!(user: user, action: 'api').value
  end

  def api_get(key:, env: {})
    get "/projects.json",
        params: { key: key },
        env: { 'REMOTE_ADDR' => '1.2.3.4' }.merge(env)
  end

  def set_block(value)
    Setting["plugin_redmine_stronger"] =
      Setting["plugin_redmine_stronger"].merge("block_internet_api" => value)
  end

  before do
    Setting.rest_api_enabled = '1'
    set_block('1')
  end

  after do
    Setting.rest_api_enabled = '0'
    set_block('')
  end

  it "blocks an API-key request coming from the internet" do
    api_get(key: api_key, env: { 'HTTP_X_PROVENANCE' => 'internet' })
    expect(response).to have_http_status(:forbidden)
  end

  it "blocks an API-key request when the provenance header is absent" do
    api_get(key: api_key)
    expect(response).to have_http_status(:forbidden)
  end

  it "allows an API-key request coming from the intranet" do
    api_get(key: api_key, env: { 'HTTP_X_PROVENANCE' => 'intranet' })
    expect(response).to have_http_status(:ok)
  end

  it "does not block when the restriction is disabled" do
    set_block('')
    api_get(key: api_key, env: { 'HTTP_X_PROVENANCE' => 'internet' })
    expect(response).to have_http_status(:ok)
  end

  it "records a 'blocked' outcome for a request rejected by the restriction" do
    api_get(key: api_key, env: { 'HTTP_X_PROVENANCE' => 'internet' })
    session = UserLoginSession.where(user_id: user.id, auth_method: 'api_key').last
    expect(session.outcome).to eq(UserLoginSession::OUTCOME_BLOCKED)
  end
end
