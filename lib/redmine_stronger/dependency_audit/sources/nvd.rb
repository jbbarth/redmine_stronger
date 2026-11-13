# frozen_string_literal: true

module RedmineStronger
  module DependencyAudit
    module Sources
      # CVEs from the NVD API 2.0, for products without a package ecosystem.
      class Nvd
        URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        CPES = { 'redmine' => 'cpe:2.3:a:redmine:redmine' }.freeze
        PAGE_SIZE = 2000

        def initialize(http)
          @http = http
        end

        def self.supports?(product)
          CPES.key?(product)
        end

        def advisories(product, version)
          cpe = "#{CPES.fetch(product)}:#{version}"
          start = 0
          advisories = []
          loop do
            query = URI.encode_www_form(virtualMatchString: cpe, resultsPerPage: PAGE_SIZE, startIndex: start)
            page = @http.get_json("#{URL}?#{query}")
            vulns = Array(page['vulnerabilities'])
            advisories.concat(vulns.map { |v| self.class.normalize(v['cve'], CPES.fetch(product)) })
            start += vulns.size
            break if vulns.empty? || start >= page['totalResults'].to_i
          end
          advisories
        end

        def self.normalize(cve, cpe_prefix)
          metric = %w(cvssMetricV40 cvssMetricV31 cvssMetricV30 cvssMetricV2)
                   .filter_map { |key| Array(cve.dig('metrics', key)).first }.first
          data = metric && metric['cvssData']
          score = data && data['baseScore']
          severity = data && data['baseSeverity'] || metric && metric['baseSeverity']
          {
            'id' => cve['id'], 'cve' => cve['id'],
            'title' => Array(cve['descriptions']).find { |d| d['lang'] == 'en' }&.dig('value').to_s.truncate(300),
            'url' => "https://nvd.nist.gov/vuln/detail/#{cve['id']}",
            'date' => cve['published'].to_s[0, 10],
            'cvss' => score&.to_f,
            'severity' => severity ? Severity.from_label(severity) : Severity.from_cvss(score),
            'fixed' => fixed_versions(cve, cpe_prefix),
            'fix_available' => fixed_versions(cve, cpe_prefix).any?,
            'source' => 'nvd'
          }
        end

        def self.fixed_versions(cve, cpe_prefix)
          Array(cve['configurations']).flat_map { |c| Array(c['nodes']) }
                                      .flat_map { |n| Array(n['cpeMatch']) }
                                      .select { |m| m['criteria'].to_s.start_with?(cpe_prefix) }
                                      .filter_map { |m| m['versionEndExcluding'] && ">= #{m['versionEndExcluding']}" }
                                      .uniq
        end
      end
    end
  end
end
