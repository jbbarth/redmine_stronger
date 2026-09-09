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
end
