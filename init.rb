# Little hack for deface in redmine:
# - redmine plugins are not railties nor engines, so deface overrides are not detected automatically
# - deface doesn't support direct loading anymore ; it unloads everything at boot so that reload in dev works
# - hack consists in adding "app/overrides" path of the plugin in Redmine's main #paths
Rails.application.paths["app/overrides"] ||= []
Rails.application.paths["app/overrides"] << File.expand_path("../app/overrides", __FILE__)

Redmine::Plugin.register :redmine_stronger do
  name "Redmine Stronger plugin"
  description "This plugin adds some security features to Redmine"
  author "Jean-Baptiste BARTH"
  author_url "mailto:jeanbaptiste.barth@gmail.com"
  requires_redmine :version_or_higher => "2.1.0"
  version "0.0.1"
  url "https://github.com/jbbarth/redmine_stronger"
end

# Patches to existing classes/modules
ActionDispatch::Callbacks.to_prepare do
  require_dependency "redmine_stronger/account_controller_patch"
end
