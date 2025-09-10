module RedmineStronger
  module RepositoriesPatch

    def self.remove_filesystem_adapter
      if Redmine::Scm::Base.all.include?("Filesystem")
        Redmine::Scm::Base.delete "Filesystem"
        puts "SCM adapter 'Filesystem' removed by RedmineStronger plugin."
      end
      puts "Available SCM adapters: #{Redmine::Scm::Base.all.inspect}"
    end

  end
end

RedmineStronger::RepositoriesPatch.remove_filesystem_adapter
