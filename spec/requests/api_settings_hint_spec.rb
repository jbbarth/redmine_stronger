require "spec_helper"

describe "API settings tab hint" do
  fixtures :users

  def log_user(login, password)
    post "/login", params: { username: login, password: password }
  end

  before { log_user("admin", "admin") }

  it "shows a link to the Stronger plugin settings on the API tab" do
    get "/settings", params: { tab: "api" }
    expect(response).to have_http_status(:ok)
    expect(response.body).to include('href="/settings/plugin/redmine_stronger"')
  end
end
