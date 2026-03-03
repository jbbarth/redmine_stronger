Redmine::Plugin.register :redmine_stronger do
  name "Redmine Stronger plugin"
  description "This plugin adds some security features to Redmine"
  author "Jean-Baptiste BARTH"
  author_url "mailto:jeanbaptiste.barth@gmail.com"
  requires_redmine :version_or_higher => "2.1.0"
  version "0.0.1"
  url "https://github.com/jbbarth/redmine_stronger"
  requires_redmine_plugin :redmine_base_rspec, :version_or_higher => '0.0.3' if Rails.env.test?
  requires_redmine_plugin :redmine_base_deface, :version_or_higher => '0.0.1'

  menu :admin_menu, :stronger_security,
       { controller: 'stronger_security', action: 'index' },
       caption: :label_stronger_security_dashboard,
       icon: 'shield-check'
end

module RedmineStronger
  class ModelHook < Redmine::Hook::Listener
    def after_plugins_loaded(_context = {})
      require_relative "lib/redmine_stronger/account_controller_patch"
      require_relative "lib/redmine_stronger/users_controller_patch"
      require_relative "lib/redmine_stronger/repositories_patch"
      require_relative "lib/redmine_stronger/hooks"
      require_relative "lib/redmine_stronger/user_patch"
      require_relative "lib/redmine_stronger/security_metrics"
    end
  end
end
