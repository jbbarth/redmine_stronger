# frozen_string_literal: true

require "spec_helper"

describe RedmineStronger::Provenance do
  describe ".classify" do
    it "returns nil for a blank value" do
      expect(described_class.classify(nil)).to be_nil
      expect(described_class.classify("")).to be_nil
    end

    it "returns :intranet when the value matches the configured intranet value" do
      expect(described_class.classify("intranet")).to eq(:intranet)
      expect(described_class.classify("INTRANET")).to eq(:intranet)
    end

    it "returns :internet for any other non-blank value" do
      expect(described_class.classify("internet")).to eq(:internet)
      expect(described_class.classify("extranet")).to eq(:internet)
    end
  end

  describe ".from_request" do
    it "reads the configured header from the request" do
      req = ActionDispatch::TestRequest.create('HTTP_X_PROVENANCE' => 'intranet')
      expect(described_class.from_request(req)).to eq('intranet')
    end

    it "returns nil when the header is absent" do
      expect(described_class.from_request(ActionDispatch::TestRequest.create)).to be_nil
    end

    it "returns nil for a nil request" do
      expect(described_class.from_request(nil)).to be_nil
    end

    it "truncates overly long values" do
      req = ActionDispatch::TestRequest.create('HTTP_X_PROVENANCE' => 'a' * 100)
      expect(described_class.from_request(req).length).to eq(described_class::MAX_LENGTH)
    end
  end

  describe "with custom settings" do
    before do
      allow(Setting).to receive(:[]).and_call_original
      allow(Setting).to receive(:[]).with('plugin_redmine_stronger').and_return(
        'provenance_header' => 'X-Zone',
        'provenance_intranet_value' => 'lan'
      )
    end

    it "honours a custom header name" do
      req = ActionDispatch::TestRequest.create('HTTP_X_ZONE' => 'lan')
      expect(described_class.from_request(req)).to eq('lan')
    end

    it "honours a custom intranet value" do
      expect(described_class.classify('lan')).to eq(:intranet)
      expect(described_class.classify('intranet')).to eq(:internet)
    end
  end
end
