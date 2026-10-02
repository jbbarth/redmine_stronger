require "spec_helper"

describe "Redmine::Scm::Base" do

  if RedmineStronger::RepositoriesPatch.core_restricts_scm_paths?
    # The core keeps Filesystem unavailable until its path regexp is configured
    it "keeps filesystem adapter unavailable without a configured path regexp" do
      Redmine::Configuration.with "scm_filesystem_path_regexp" => "" do
        expect(Repository::Filesystem.scm_available).to be_falsey
      end
    end
  else
    # Ensure the filesystem adapter is not loaded
    it "removes filesystem adapter" do
      expect(Redmine::Scm::Base.all).to include("Git")
      expect(Redmine::Scm::Base.all).to_not include("Filesystem")
    end
  end

end
