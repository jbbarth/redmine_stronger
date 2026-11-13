# frozen_string_literal: true

module RedmineStronger
  module DependencyAudit
    module Sources
      # Debian security tracker: status of every CVE per source package and release.
      # The full dump is large (about 90 MB), so it is only loaded by the collector.
      class DebianTracker
        URL = 'https://security-tracker.debian.org/tracker/data/json'

        def self.download(http, url: URL)
          new(JSON.parse(http.get(url)))
        end

        def initialize(data)
          @data = data
        end

        # Releases the tracker still follows. An end of life release disappears
        # from the dump: its packages no longer get security tracking.
        def tracked?(codename)
          @tracked ||= %w(openssl libxml2 glibc).flat_map { |pkg| (@data[pkg] || {}).values.first&.dig('releases')&.keys || [] }.to_set
          @tracked.include?(codename)
        end

        def advisories(source, version, codename)
          (@data[source] || {}).filter_map do |cve_id, cve|
            release = cve.dig('releases', codename)
            next unless release

            self.class.advisory(cve_id, cve, release, version)
          end
        end

        def self.advisory(cve_id, cve, release, version)
          fixed = release['fixed_version']
          case release['status']
          when 'resolved'
            return if fixed.blank? || fixed == '0'
            return if DebianVersion.compare(version, fixed) >= 0

            fix_available = true
          when 'open', 'undetermined'
            fix_available = false
          else
            return
          end

          {
            'id' => cve_id, 'cve' => cve_id.start_with?('CVE-') ? cve_id : nil,
            'title' => cve['description'].to_s.truncate(300),
            'url' => "https://security-tracker.debian.org/tracker/#{cve_id}",
            'severity' => Severity.from_label(release['urgency']),
            'fixed' => fix_available ? [fixed] : [],
            'fix_available' => fix_available,
            'source' => 'debian'
          }
        end
      end
    end
  end
end
