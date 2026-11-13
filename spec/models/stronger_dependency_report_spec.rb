# frozen_string_literal: true

require "spec_helper"

describe StrongerDependencyReport do
  it "shows a requested collection as running until it is completed" do
    request = described_class.request!
    expect(described_class.running).to eq request
    expect(described_class.latest).to be_nil

    described_class.record!({ "gems" => [] }, report: request)
    expect(described_class.running).to be_nil
    expect(described_class.latest).to eq request
  end

  it "considers a collection running for too long as abandoned" do
    request = described_class.request!
    request.update!(requested_at: (described_class::RUN_TIMEOUT + 1.minute).ago)
    expect(described_class.running).to be_nil
    expect(described_class.failed_request).to eq request
  end

  it "keeps only the last request besides the completed reports" do
    described_class.request!.fail!("boom")
    last = described_class.request!
    expect(described_class.where.not(status: "done")).to eq [last]
  end
end
