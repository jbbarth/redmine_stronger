# frozen_string_literal: true

require "spec_helper"

describe StrongerDependencyAuditJob do
  let(:job) { described_class.new }
  let(:request) { StrongerDependencyReport.request! }

  def exit_status(code)
    instance_double(Process::Status, exitstatus: code)
  end

  it "leaves the report recorded by the task as is, even with vulnerabilities" do
    allow(job).to receive(:run_task) do |report|
      StrongerDependencyReport.record!({ "gems" => [] }, report: report)
      ["Dependency audit recorded", exit_status(2)]
    end
    job.perform(request.id)
    expect(request.reload).to be_done
  end

  it "marks the request as failed with the end of the output when the task did not record" do
    allow(job).to receive(:run_task).and_return(["booting\nrake aborted!\nPG::ConnectionBad\n", exit_status(1)])
    job.perform(request.id)
    expect(request.reload).to be_failed
    expect(request.error).to include("PG::ConnectionBad")
  end

  it "keeps the error message rather than the end of the backtrace" do
    output = <<~OUTPUT
      bin/rails aborted!
      NoMethodError: undefined method 'foo' for nil
      /opt/redmine/plugins/redmine_stronger/lib/a.rb:12:in 'block in run'
      /usr/local/rvm/gems/ruby-4.0.9/gems/railties-8.1.4.1/lib/rails/command.rb:143:in 'Rails::Command.with_argv'
      /usr/local/rvm/gems/ruby-4.0.9/gems/railties-8.1.4.1/lib/rails/command.rb:63:in 'Rails::Command.invoke'
      /usr/local/rvm/gems/ruby-4.0.9/gems/railties-8.1.4.1/lib/rails/commands.rb:18:in '<top (required)>'
      /opt/redmine/bin/rails:4:in '<main>'
      (See full trace by running task with --trace)
    OUTPUT
    allow(job).to receive(:run_task).and_return([output, exit_status(1)])
    job.perform(request.id)
    expect(request.reload.error).to eq("bin/rails aborted!\nNoMethodError: undefined method 'foo' for nil")
  end

  it "ignores a request that is no longer running" do
    request.fail!("boom")
    expect(job).not_to receive(:run_task)
    job.perform(request.id)
  end
end
