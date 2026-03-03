# frozen_string_literal: true

require "spec_helper"

describe StrongerSecurityController do
  fixtures :users, :roles, :projects, :members, :member_roles,
           :issues, :issue_statuses, :trackers, :enabled_modules

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


      it "assigns @inactive_users_count as an integer" do
        get :index
        expect(assigns(:inactive_users_count)).to be_a(Integer)
      end

      it "assigns @locked_users" do
        get :index
        expect(assigns(:locked_users)).to be_present.or(be_empty)
      end
    end
  end
end
