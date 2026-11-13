# frozen_string_literal: true

module RedmineStronger
  module DependencyAudit
    module Sources
      # Advisories from OSV.dev. Only used for public npm libraries
      # (name and version), never for the gem or system inventory.
      class Osv
        BATCH_URL = 'https://api.osv.dev/v1/querybatch'
        VULN_URL  = 'https://api.osv.dev/v1/vulns/%s'

        attr_reader :errors

        def initialize(http, threads: 8)
          @http = http
          @threads = threads
          @errors = []
        end

        # packages: [[name, version], ...] => { [name, version] => [advisory, ...] }
        def advisories(packages, ecosystem: 'npm')
          return {} if packages.empty?

          queries = packages.map { |name, version| { package: { name: name, ecosystem: ecosystem }, version: version } }
          results = Array(@http.post_json(BATCH_URL, queries: queries)['results'])
          ids = packages.zip(results).to_h { |package, result| [package, Array(result && result['vulns']).pluck('id')] }

          details = {}
          mutex = Mutex.new
          ParallelMap.each(ids.values.flatten.uniq, threads: @threads) do |id|
            vuln = @http.get_json(format(VULN_URL, id))
            mutex.synchronize { details[id] = vuln }
          rescue Http::Error => e
            mutex.synchronize { @errors << e.message }
          end

          # A vulnerability whose details could not be fetched is still reported.
          ids.to_h do |(name, version), vuln_ids|
            [[name, version], vuln_ids.map { |id| details[id] ? self.class.normalize(details[id], name) : self.class.stub(id) }]
          end
        end

        def self.stub(id)
          { 'id' => id, 'url' => "https://osv.dev/vulnerability/#{id}", 'severity' => 'unknown',
            'fixed' => [], 'fix_available' => false, 'source' => 'osv' }
        end

        def self.normalize(vuln, package)
          aliases = Array(vuln['aliases'])
          cve = aliases.find { |a| a.start_with?('CVE-') }
          ghsa = ([vuln['id']] + aliases).find { |a| a.start_with?('GHSA-') }
          fixed = Array(vuln['affected']).select { |a| a.dig('package', 'name') == package }
                                         .flat_map { |a| Array(a['ranges']) }
                                         .flat_map { |r| Array(r['events']) }
                                         .filter_map { |e| e['fixed'] && ">= #{e['fixed']}" }.uniq
          {
            'id' => cve || ghsa || vuln['id'], 'cve' => cve, 'ghsa' => ghsa,
            'title' => (vuln['summary'].presence || vuln['details'].to_s).truncate(300),
            'url' => ghsa ? "https://github.com/advisories/#{ghsa}" : "https://osv.dev/vulnerability/#{vuln['id']}",
            'date' => vuln['published'].to_s[0, 10],
            'severity' => Severity.from_label(vuln.dig('database_specific', 'severity')),
            'fixed' => fixed, 'fix_available' => fixed.any?,
            'source' => 'osv'
          }
        end
      end
    end
  end
end
