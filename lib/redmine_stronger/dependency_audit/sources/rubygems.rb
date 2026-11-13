# frozen_string_literal: true

module RedmineStronger
  module DependencyAudit
    module Sources
      # Latest gem versions from the rubygems.org compact index (what Bundler uses).
      class Rubygems
        INFO_URL = 'https://index.rubygems.org/info/%s'

        def initialize(http, threads: 8)
          @http = http
          @threads = threads
        end

        # Returns [{ name => [Gem::Version, ...] }, { name => error message }]
        def versions(names)
          results = {}
          errors = {}
          mutex = Mutex.new
          ParallelMap.each(names, threads: @threads) do |name|
            versions = self.class.parse_info(@http.get(format(INFO_URL, name)))
            mutex.synchronize { results[name] = versions }
          rescue Http::Error => e
            mutex.synchronize { errors[name] = e.message }
          end
          [results, errors]
        end

        # Lines look like "1.19.7-x86_64-linux deps|checksum:...": the version is
        # before the first space, the platform after the first dash.
        def self.parse_info(body)
          body.each_line.filter_map do |line|
            next if line.start_with?('---')

            number = line.split(' ', 2).first.to_s.split('-', 2).first
            next unless Gem::Version.correct?(number)

            version = Gem::Version.new(number)
            version unless version.prerelease?
          end.uniq.sort
        end

        # Latest overall and latest of the same major.minor branch.
        def self.summarize(versions, current)
          return {} if versions.blank?

          current = Gem::Version.new(current)
          branch = current.segments.first(2)
          {
            'latest' => versions.max.to_s,
            'branch_latest' => versions.select { |v| v.segments.first(2) == branch }.max&.to_s
          }
        end
      end
    end
  end
end
