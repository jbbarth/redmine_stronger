require "spec_helper"

describe "Redmine::Scm::Base" do

  # Ensure the filesystem adapter is not loaded
  it "removes filesystem adapter" do
    expect(Redmine::Scm::Base.all).to include("Git")
    expect(Redmine::Scm::Base.all).to_not include("Filesystem")
  end

end
