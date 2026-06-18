# frozen_string_literal: true

module RedmineStronger
  # Detects the network zone (intranet / internet) a request comes from
  module Provenance
    DEFAULT_HEADER = 'X-Provenance'
    DEFAULT_INTRANET_VALUE = 'intranet'
    MAX_LENGTH = 64

    def self.header_name
      setting('provenance_header') || DEFAULT_HEADER
    end

    def self.intranet_value
      setting('provenance_intranet_value') || DEFAULT_INTRANET_VALUE
    end

    # Raw header value captured at request time (truncated), or nil when absent.
    def self.from_request(req)
      return nil unless req
      req.headers[header_name].presence&.slice(0, MAX_LENGTH)
    end

    # Classifies a stored raw value into :intranet / :internet, or nil if blank.
    def self.classify(raw)
      return nil if raw.blank?
      raw.casecmp?(intranet_value) ? :intranet : :internet
    end

    # True only when the request explicitly comes from the intranet zone.
    # A missing/blank provenance header is therefore treated as non-intranet.
    def self.intranet?(req)
      classify(from_request(req)) == :intranet
    end

    def self.setting(key)
      Setting['plugin_redmine_stronger'][key].presence
    rescue StandardError
      nil
    end
    private_class_method :setting
  end
end
