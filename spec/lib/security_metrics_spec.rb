# frozen_string_literal: true

require "spec_helper"

describe RedmineStronger::SecurityMetrics do
  fixtures :users, :roles, :projects, :members, :member_roles,
           :issues, :issue_statuses, :trackers, :enabled_modules,
           :wikis, :wiki_pages, :attachments

  describe ".inactive_users" do
    it "returns active users who haven't logged in recently" do
      inactive = described_class.inactive_users
      inactive.each do |user|
        expect(user.active?).to be true
        if user.last_login_on
          expect(user.last_login_on).to be < RedmineStronger::SecurityMetrics::INACTIVE_DAYS.days.ago
        end
      end
    end

    it "is limited to INACTIVE_USERS_LIMIT records" do
      expect(described_class.inactive_users.size).to be <= RedmineStronger::SecurityMetrics::INACTIVE_USERS_LIMIT
    end

    it "excludes users who used the API recently even if they never logged in via the web" do
      user = User.find(2)
      user.update_column(:last_login_on, nil)
      expect(described_class.inactive_users_scope).to include(user)

      Token.create!(user: user, action: 'api', value: 'a' * 40, last_used_at: 1.day.ago)
      expect(described_class.inactive_users_scope).not_to include(user)
    end

    it "still considers users inactive when their API token is stale" do
      user = User.find(2)
      user.update_column(:last_login_on, nil)
      Token.create!(user: user, action: 'api', value: 'b' * 40,
                    last_used_at: (RedmineStronger::SecurityMetrics::INACTIVE_DAYS + 1).days.ago)

      expect(described_class.inactive_users_scope).to include(user)
    end
  end

  describe ".api_users_scope" do
    it "returns only API tokens that have been used, most recently used first" do
      old   = Token.create!(user: User.find(2), action: 'api', value: 'a' * 40, last_used_at: 2.days.ago)
      recent = Token.create!(user: User.find(3), action: 'api', value: 'b' * 40, last_used_at: 1.hour.ago)
      Token.create!(user: User.find(4), action: 'api', value: 'c' * 40, last_used_at: nil)

      result = described_class.api_users_scope.to_a

      expect(result).to include(old, recent)
      expect(result.map(&:last_used_at)).to eq(result.map(&:last_used_at).sort.reverse)
      expect(result).to all(satisfy { |t| t.action == 'api' && t.last_used_at.present? })
    end

    it "is an unlimited scope the controller paginates" do
      expect(described_class.api_users_scope.limit_value).to be_nil
    end
  end

  describe ".api_user_provenances" do
    let(:user) { User.find(2) }

    it "returns the most recent provenance per user from api_key sessions" do
      UserLoginSession.create!(user: user, logged_in_at: 2.days.ago, auth_method: 'api_key', provenance: 'internet')
      UserLoginSession.create!(user: user, logged_in_at: 1.hour.ago, auth_method: 'api_key', provenance: 'intranet')

      expect(described_class.api_user_provenances([user.id])).to eq(user.id => 'intranet')
    end

    it "ignores sessions without a provenance" do
      UserLoginSession.create!(user: user, logged_in_at: 1.hour.ago, auth_method: 'api_key', provenance: nil)

      expect(described_class.api_user_provenances([user.id])).to eq({})
    end

    it "ignores non-api_key sessions" do
      UserLoginSession.create!(user: user, logged_in_at: 1.hour.ago, auth_method: 'password', provenance: 'intranet')

      expect(described_class.api_user_provenances([user.id])).to eq({})
    end

    it "returns an empty hash when given no user ids" do
      expect(described_class.api_user_provenances([])).to eq({})
    end
  end

  describe ".inactive_users_count" do
    it "returns an integer" do
      expect(described_class.inactive_users_count).to be_a(Integer)
    end
  end

  describe ".inactive_admins" do
    it "returns inactive users who are admins or sudoers" do
      admin = User.find_by_login("admin")
      admin.update_column(:last_login_on, (RedmineStronger::SecurityMetrics::INACTIVE_DAYS + 1).days.ago)

      result = described_class.inactive_admins
      expect(result).to include(admin)
      result.each do |user|
        is_admin = user.admin? || (user.respond_to?(:sudoer?) && user.sudoer?)
        expect(is_admin).to be true
      end
    end

    it "excludes recently active admins" do
      admin = User.find_by_login("admin")
      admin.update_column(:last_login_on, Time.now)

      expect(described_class.inactive_admins).not_to include(admin)
    end
  end

  describe ".non_member_user" do
    it "returns an active user with no membership and the builtin Non member role" do
      user = described_class.non_member_user

      expect(user).to be_active
      expect(user.id).to eq(0)
      expect(user.memberships).to be_empty
      expect(user.builtin_role).to eq(Role.non_member)
    end
  end

  describe ".exposed_wikis" do
    def wiki_rows
      described_class.exposed_wikis(described_class.non_member_user)[:wiki]
    end

    before do
      expect(Role.non_member.has_permission?(:view_wiki_pages)).to be true
    end

    it "lists the public projects whose wiki a non-member can read" do
      expect(wiki_rows.map {|row| row.project.id}).to include(1)
    end

    it "counts the pages and the attached files disclosed by an exposed wiki" do
      row = wiki_rows.detect {|r| r.project.id == 1}

      expect(row.pages).to eq(WikiPage.where(wiki_id: 1).count)
      expect(row.attachments).to eq(Attachment.where(container_type: 'WikiPage', container_id: WikiPage.where(wiki_id: 1).ids).count)
    end

    it "excludes private projects" do
      expect(wiki_rows.map {|row| row.project.id}).not_to include(2)
    end

    it "excludes projects whose wiki module is disabled" do
      EnabledModule.where(project_id: 1, name: 'wiki').destroy_all

      expect(wiki_rows.map {|row| row.project.id}).not_to include(1)
    end

    it "excludes projects once the Non member role loses the permission" do
      Role.non_member.remove_permission!(:view_wiki_pages)

      expect(described_class.exposed_wikis(described_class.non_member_user)[:wiki]).to be_empty
    end

    it "orders projects by the amount of content they disclose" do
      pages = wiki_rows.map(&:pages)

      expect(pages).to eq(pages.sort.reverse)
    end

    context "with the Documentation tab of redmine_second_wiki" do
      before do
        skip "redmine_second_wiki is not installed" unless described_class.documentation_supported?

        EnabledModule.create!(project_id: 1, name: 'documentation')
        Role.non_member.add_permission!(:view_documentation_pages)

        wiki = Wiki.find(1)
        root = WikiPage.create!(wiki: wiki, title: wiki.documentation_start_page.tr(' ', '_'))
        WikiPage.create!(wiki: wiki, title: 'Doc_child', parent_id: root.id)
      end

      it "counts the documentation subtree apart from the wiki" do
        result = described_class.exposed_wikis(described_class.non_member_user)
        documentation = result[:documentation].detect {|row| row.project.id == 1}

        expect(documentation.pages).to eq(2)
      end

      it "leaves a wiki start page nested under the documentation root on the wiki side" do
        wiki = Wiki.find(1)
        root = wiki.find_page(wiki.documentation_start_page)
        wiki.find_page(wiki.start_page).update_column(:parent_id, root.id)

        result = described_class.exposed_wikis(described_class.non_member_user)

        expect(result[:documentation].detect {|row| row.project.id == 1}.pages).to eq(2)
      end

      it "splits the pages of a project between the two tabs without overlap" do
        result = described_class.exposed_wikis(described_class.non_member_user)
        wiki_pages = result[:wiki].detect {|row| row.project.id == 1}.pages
        documentation_pages = result[:documentation].detect {|row| row.project.id == 1}.pages

        expect(wiki_pages + documentation_pages).to eq(WikiPage.where(wiki_id: 1).count)
      end
    end
  end

  describe ".module_enabled_projects_count" do
    it "counts the non-archived projects with the module enabled" do
      expect(described_class.module_enabled_projects_count(:wiki)).
        to eq(Project.where(status: [Project::STATUS_ACTIVE, Project::STATUS_CLOSED]).has_module(:wiki).count)
    end
  end
end
