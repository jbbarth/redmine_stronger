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
end

# Patches to existing classes/modules
ActiveSupport::Reloader.to_prepare do
  require_dependency "redmine_stronger/account_controller_patch"
  require_dependency "redmine_stronger/users_controller_patch"
end
