module RedmineStronger
  module RepositoriesPatch

    # Redmine versions that only make a SCM available once its
    # scm_<name>_path_regexp is configured already keep Filesystem disabled
    # unless the system administrator explicitly allows it.
    def self.core_restricts_scm_paths?
      Repository.respond_to?(:scm_path_regexp)
    end

    def self.remove_filesystem_adapter
      return if core_restricts_scm_paths?

      if Redmine::Scm::Base.all.include?("Filesystem")
        Redmine::Scm::Base.delete "Filesystem"
        puts "SCM adapter 'Filesystem' removed by RedmineStronger plugin."
      end
      puts "Available SCM adapters: #{Redmine::Scm::Base.all.inspect}"
    end

  end
end

RedmineStronger::RepositoriesPatch.remove_filesystem_adapter
