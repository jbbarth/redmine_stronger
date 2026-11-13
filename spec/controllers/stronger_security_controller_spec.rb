# frozen_string_literal: true

require "spec_helper"

describe StrongerSecurityController do
  fixtures :users, :roles, :projects, :members, :member_roles,
           :issues, :issue_statuses, :trackers, :enabled_modules,
           :wikis, :wiki_pages, :attachments

  describe "GET #index" do
    context "as a non-admin user" do
      before { User.current = nil }

      it "redirects to login" do
        get :index
        expect(response.location).to include(signin_path)
      end
    end

    context "as an admin user" do
      before do
        @request.session[:user_id] = User.find_by_login("admin").id
      end

      it "returns 200" do
        get :index
        expect(response).to be_successful
      end

      it "assigns @anon_total as an integer" do
        get :index
        expect(assigns(:anon_total)).to be_a(Integer)
      end

      it "assigns @anon_open <= @anon_total" do
        get :index
        expect(assigns(:anon_open)).to be <= assigns(:anon_total)
      end

      it "assigns @non_member_total as an integer" do
        get :index
        expect(assigns(:non_member_total)).to be_a(Integer)
      end

      it "assigns @non_member_open <= @non_member_total" do
        get :index
        expect(assigns(:non_member_open)).to be <= assigns(:non_member_total)
      end

      it "assigns @exposed_wikis with a project, a page count and an attachment count per row" do
        get :index
        expect(assigns(:exposed_wikis)).to all(have_attributes(project: be_a(Project),
                                                               pages: be_a(Integer),
                                                               attachments: be_a(Integer)))
      end

      it "assigns fewer exposed wikis than projects with the wiki module enabled" do
        get :index
        expect(assigns(:exposed_wikis).size).to be <= assigns(:wiki_projects_count)
      end

      it "assigns @exposed_documentations only when redmine_second_wiki is installed" do
        get :index
        if assigns(:documentation_supported)
          expect(assigns(:exposed_documentations)).to be_an(Array)
        else
          expect(assigns(:exposed_documentations)).to be_empty
        end
      end

      it "assigns @inactive_users_count as an integer" do
        get :index
        expect(assigns(:inactive_users_count)).to be_a(Integer)
      end

      it "assigns @locked_users" do
        get :index
        expect(assigns(:locked_users)).to be_present.or(be_empty)
      end

      it "assigns @api_user_outcomes mapping the latest API outcome per user" do
        admin = User.find_by_login("admin")
        UserLoginSession.create!(user: admin, logged_in_at: Time.now, auth_method: 'api_key',
                                 outcome: UserLoginSession::OUTCOME_DENIED)
        Token.create!(user: admin, action: 'api', last_used_at: Time.now)

        get :index
        expect(assigns(:api_user_outcomes)[admin.id]).to eq(UserLoginSession::OUTCOME_DENIED)
      end

      it "lists the API accounts with blocked attempts first" do
        Token.create!(user: User.find(2), action: 'api', last_used_at: 1.hour.ago)
        Token.create!(user: User.find(3), action: 'api', last_used_at: 3.days.ago)
        UserLoginSession.create!(user: User.find(3), logged_in_at: 3.days.ago, auth_method: 'api_key',
                                 outcome: UserLoginSession::OUTCOME_BLOCKED)

        get :index
        expect(assigns(:api_users).map(&:user_id).first(2)).to eq [3, 2]
      end

      context "rendering the page" do
        render_views

        it "renders the wiki exposure box with a link to each exposed project" do
          get :index

          expect(response.body).to include(I18n.t(:stronger_column_wiki_pages))
          assigns(:exposed_wikis).each do |row|
            expect(response.body).to include(settings_project_path(row.project))
          end
        end

        it "renders the Documentation exposure box when redmine_second_wiki is installed" do
          skip "redmine_second_wiki is not installed" unless RedmineStronger::SecurityMetrics.documentation_supported?

          project = Project.find(1)
          EnabledModule.create!(project: project, name: 'documentation')
          Role.non_member.add_permission!(:view_documentation_pages)
          WikiPage.create!(wiki: project.wiki, title: project.wiki.documentation_start_page.tr(' ', '_'))

          get :index

          expect(response.body).to include(project_documentation_index_path(project))
        end
      end
    end
  end

  describe "GET #dependencies" do
    render_views

    let(:payload) do
      {
        "sources" => %w(advisories),
        "environment" => [{ "kind" => "redmine", "name" => "Redmine", "version" => "7.0.1", "cycle" => "7.0",
                            "branch_latest" => "7.0.3", "eol" => false,
                            "advisories" => [{ "id" => "CVE-2026-0001", "severity" => "high", "fix_available" => true,
                                               "fixed" => [">= 7.0.2"], "url" => "https://nvd.example/CVE-2026-0001" }] }],
        "gems" => [{ "name" => "rack", "version" => "3.2.6", "direct" => false, "branch_latest" => "3.2.7", "advisories" => [] },
                   { "name" => "rails", "version" => "8.1.4.1", "direct" => true, "branch_latest" => "8.1.4.1", "advisories" => [] }],
        "packages" => [], "packages_total" => 0, "package_tracking" => "untracked",
        "javascripts" => [], "plugins" => [{ "name" => "redmine_stronger", "commit" => "a" * 40, "up_to_date" => false,
                                             "remote_commit" => "b" * 40 }],
        "errors" => [{ "source" => "nvd", "message" => "HTTP 503" }]
      }
    end

    it "redirects non-admin users to login" do
      get :dependencies
      expect(response.location).to include(signin_path)
    end

    context "as an admin user" do
      before { @request.session[:user_id] = User.find_by_login("admin").id }

      it "explains how to collect when no audit was recorded" do
        get :dependencies
        expect(response).to be_successful
        expect(response.body).to include("redmine:stronger:audit_dependencies")
      end

      it "renders the latest audit with its advisories and source errors" do
        StrongerDependencyReport.record!(payload)
        get :dependencies
        expect(response).to be_successful
        expect(response.body).to include("CVE-2026-0001", "HTTP 503", "rack", "3.2.7", "/issues/new?issue")
      end

      it "does not present an incomplete audit as free of vulnerabilities" do
        payload["environment"].first["advisories"] = []
        payload["gems"].each { |gem| gem.delete("advisories") }
        StrongerDependencyReport.record!(payload)
        get :dependencies
        expect(response.body).to include(I18n.t(:stronger_dependencies_no_advisory_incomplete), I18n.t(:stronger_not_checked))
        expect(response.body).not_to include(I18n.t(:stronger_dependencies_no_advisory))
      end

      it "does not link advisories to non http urls" do
        payload["environment"].first["advisories"].first["url"] = "javascript:alert(1)"
        StrongerDependencyReport.record!(payload)
        get :dependencies
        expect(response.body).not_to include("javascript:alert")
      end

      it "shows a collection in progress" do
        StrongerDependencyReport.request!
        get :dependencies
        expect(response.body).to include(I18n.t(:stronger_dependencies_running, time: "")[0, 20])
        expect(response.body).not_to include(I18n.t(:stronger_dependencies_collect))
      end

      it "shows why the last requested collection failed" do
        StrongerDependencyReport.record!(payload)
        StrongerDependencyReport.request!.fail!("rake aborted!")
        get :dependencies
        expect(response.body).to include("rake aborted!")
      end
    end
  end

  describe "POST #collect_dependencies" do
    it "is reserved to administrators" do
      expect(StrongerDependencyAuditJob).not_to receive(:perform_later)
      post :collect_dependencies
      expect(StrongerDependencyReport.count).to eq 0
    end

    context "as an admin user" do
      before { @request.session[:user_id] = User.find_by_login("admin").id }

      it "requests a collection in the background" do
        expect(StrongerDependencyAuditJob).to receive(:perform_later).with(kind_of(Integer))
        post :collect_dependencies
        expect(response).to redirect_to(stronger_security_dependencies_path)
        expect(StrongerDependencyReport.running).to be_present
      end

      it "does not start a second collection while one is running" do
        StrongerDependencyReport.request!
        expect(StrongerDependencyAuditJob).not_to receive(:perform_later)
        post :collect_dependencies
        expect(StrongerDependencyReport.count).to eq 1
      end
    end
  end
end
