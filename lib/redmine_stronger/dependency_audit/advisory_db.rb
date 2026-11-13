# frozen_string_literal: true

require 'rubygems/package'
require 'zlib'
require 'stringio'
require 'yaml'

module RedmineStronger
  module DependencyAudit
    # Advisories of ruby-advisory-db (the database bundler-audit uses),
    # downloaded as an archive and matched locally: the gem inventory
    # is never sent anywhere.
    class AdvisoryDb
      ARCHIVE_URL = 'https://codeload.github.com/rubysec/ruby-advisory-db/tar.gz/refs/heads/master'
      ENTRY = %r{\A[^/]+/(gems|rubies)/([^/]+)/[^/]+\.ya?ml\z}

      def self.download(http, url: ARCHIVE_URL)
        new(parse_archive(http.get(url)))
      end

      # Returns { 'gems' => { name => [advisory, ...] }, 'rubies' => { engine => [...] } }
      def self.parse_archive(bytes)
        index = { 'gems' => Hash.new { |h, k| h[k] = [] }, 'rubies' => Hash.new { |h, k| h[k] = [] } }
        Zlib::GzipReader.wrap(StringIO.new(bytes)) do |gzip|
          Gem::Package::TarReader.new(gzip).each do |entry|
            next unless entry.file?

            match = ENTRY.match(entry.full_name)
            next unless match

            advisory = YAML.safe_load(entry.read, permitted_classes: [Date], aliases: false)
            index[match[1]][match[2]] << advisory if advisory.is_a?(Hash)
          end
        end
        index
      end

      def initialize(index)
        @index = index
      end

      def size
        @index.values.sum { |by_name| by_name.values.sum(&:size) }
      end

      def for_gem(name, version)
        matching(@index['gems'][name], version)
      end

      def for_ruby(engine, version)
        matching(@index['rubies'][engine], version)
      end

      def self.vulnerable?(advisory, version)
        version = Gem::Version.new(version)
        return false if requirements(advisory['unaffected_versions']).any? { |req| req.satisfied_by?(version) }

        requirements(advisory['patched_versions']).none? { |req| req.satisfied_by?(version) }
      end

      def self.requirements(list)
        Array(list).map { |constraint| Gem::Requirement.new(*constraint.to_s.split(',').map(&:strip)) }
      end

      def self.normalize(advisory)
        cvss = advisory['cvss_v4'] || advisory['cvss_v3'] || advisory['cvss_v2']
        {
          'id' => identifier(advisory),
          'cve' => advisory['cve'] && "CVE-#{advisory['cve']}",
          'ghsa' => advisory['ghsa'] && "GHSA-#{advisory['ghsa']}",
          'title' => advisory['title'].to_s.strip,
          'url' => advisory['url'],
          'date' => advisory['date']&.to_s,
          'cvss' => cvss&.to_f,
          'severity' => Severity.from_cvss(cvss, v2: advisory['cvss_v4'].nil? && advisory['cvss_v3'].nil?),
          'fixed' => Array(advisory['patched_versions']).map(&:to_s),
          'fix_available' => Array(advisory['patched_versions']).any?,
          'source' => 'ruby-advisory-db'
        }
      end

      def self.identifier(advisory)
        if advisory['cve']
          "CVE-#{advisory['cve']}"
        elsif advisory['ghsa']
          "GHSA-#{advisory['ghsa']}"
        else
          advisory['osvdb'] ? "OSVDB-#{advisory['osvdb']}" : advisory['title'].to_s
        end
      end

      private

      def matching(advisories, version)
        Array(advisories).select { |advisory| self.class.vulnerable?(advisory, version) }
                         .map { |advisory| self.class.normalize(advisory) }
      rescue ArgumentError
        # Malformed version or constraint
        []
      end
    end
  end
end
