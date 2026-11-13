# frozen_string_literal: true

module RedmineStronger
  module DependencyAudit
    module Sources
      # Release cycles and support dates from endoflife.date.
      class EndOfLife
        URL = 'https://endoflife.date/api/v1/products/%s'

        def initialize(http)
          @http = http
        end

        def releases(product)
          Array(@http.get_json(format(URL, product)).dig('result', 'releases'))
        end

        # The release cycle a version belongs to: the longest cycle name
        # whose segments start the version ("7.0" for 7.0.3, "17" for 17.11).
        def self.release_for(releases, version)
          segments = version.to_s.split('.')
          releases.select { |r| segments.first(r['name'].to_s.split('.').size) == r['name'].to_s.split('.') }
                  .max_by { |r| r['name'].to_s.split('.').size }
        end

        def self.summarize(releases, version)
          release = release_for(releases, version)
          newest = releases.max_by { |r| r['releaseDate'].to_s }
          summary = { 'latest' => newest&.dig('latest', 'name') }
          return summary.merge('cycle_unknown' => true) unless release

          summary.merge(
            'cycle' => release['name'],
            'branch_latest' => release.dig('latest', 'name'),
            'eol' => release['isEol'] == true,
            'eol_date' => release['eolFrom'],
            'security_only' => release['isEoas'] == true && release['isEol'] != true,
            'active_support_end' => release['eoasFrom'],
            'extended_support_end' => release['eoesFrom']
          )
        end
      end
    end
  end
end
