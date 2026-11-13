# frozen_string_literal: true

module RedmineStronger
  module DependencyAudit
    # Builds the dependency audit snapshot: local inventory, enriched by each
    # network source. A failing source is recorded in 'errors' and the others
    # still contribute.
    class Collector
      SOURCES = %w(advisories rubygems endoflife nvd debian npm osv git).freeze
      SCHEMA  = 1

      attr_reader :errors

      def initialize(http: Http.new, inventory: Inventory.new, sources: SOURCES, offline: false,
                     advisory_db: nil, debian_tracker: nil)
        @http = http
        @inventory = inventory
        @sources = offline ? [] : sources.map(&:to_s) & SOURCES
        @advisory_db = advisory_db
        @debian_tracker = debian_tracker
        @errors = []
      end

      def run
        environment = @inventory.environment
        gems        = @inventory.gems
        packages    = @inventory.packages
        javascripts = @inventory.javascripts
        plugins     = @inventory.plugins
        os          = environment.find { |item| item['kind'] == 'os' } || {}

        advisory_db = source('advisories') { @advisory_db || AdvisoryDb.download(@http) }
        enrich_gems(gems, advisory_db)
        enrich_environment(environment, advisory_db)
        package_tracking = enrich_packages(packages, os)
        enrich_javascripts(javascripts)
        enrich_plugins(plugins)

        {
          'schema' => SCHEMA,
          'sources' => @sources,
          'environment' => environment,
          'gems' => gems,
          'packages' => packages.select { |p| p['key'] || p['advisories'].present? || p['candidate'] },
          'packages_total' => packages.size,
          'package_tracking' => package_tracking,
          'javascripts' => javascripts,
          'plugins' => plugins,
          'errors' => @errors
        }
      end

      # Number of critical or high advisories in a snapshot.
      def self.alert_count(payload)
        StrongerDependencyReport::CATEGORIES.sum do |category|
          Array(payload[category]).sum do |item|
            Array(item['advisories']).count { |a| Severity::ALERT.include?(a['severity']) }
          end
        end
      end

      private

      def enabled?(name)
        @sources.include?(name)
      end

      def source(name)
        return unless enabled?(name)

        yield
      rescue StandardError => e
        @errors << { 'source' => name, 'message' => "#{e.class}: #{e.message}".truncate(500) }
        nil
      end

      def enrich_gems(gems, advisory_db)
        if advisory_db
          gems.each { |gem| gem['advisories'] = advisory_db.for_gem(gem['name'], gem['version']) }
        end

        source('rubygems') do
          names = gems.select { |g| g['rubygems'] }.pluck('name')
          versions, failures = Sources::Rubygems.new(@http).versions(names)
          gems.each { |gem| gem.merge!(Sources::Rubygems.summarize(versions[gem['name']], gem['version'])) }
          if failures.any?
            @errors << { 'source' => 'rubygems',
                         'message' => "#{failures.size} gems not found: #{failures.keys.first(10).join(', ')}" }
          end
        end
      end

      def enrich_environment(environment, advisory_db)
        environment.each do |item|
          if item['kind'] == 'ruby' && advisory_db
            item['advisories'] = advisory_db.for_ruby(item['engine'], item['version'])
          end

          if item['product'].present? && item['version'].present?
            source('endoflife') do
              item.merge!(Sources::EndOfLife.summarize(Sources::EndOfLife.new(@http).releases(item['product']),
                                                       item['version']))
            end
          end

          if Sources::Nvd.supports?(item['product'])
            # NVD often lacks the affected versions of recent CVEs: an empty
            # result does not prove the version is safe.
            item['coverage'] = 'partial'
            source('nvd') { item['advisories'] = Sources::Nvd.new(@http).advisories(item['product'], item['version']) }
          end
          # Rails is audited through its gems (actionpack, activerecord...).
          item['coverage'] = 'gems' if item['kind'] == 'rails'
        end
      end

      # Returns 'tracked', 'untracked' (release no longer followed by the
      # Debian security team) or 'unsupported' (not Debian, or source disabled).
      def enrich_packages(packages, os)
        return 'unsupported' if packages.empty? || os['product'] != 'debian' || os['codename'].blank?

        tracker = source('debian') { @debian_tracker || Sources::DebianTracker.download(@http) }
        return 'unsupported' unless tracker
        return 'untracked' unless tracker.tracked?(os['codename'])

        # About half the packages of a Debian system have open CVEs, mostly
        # unrated and without fix: outside key packages, only those with a
        # published fix (an upgrade to apply) are kept.
        packages.each do |package|
          advisories = tracker.advisories(package['name'], package['version'], os['codename'])
                              .reject { |advisory| advisory['severity'] == 'negligible' }
          advisories.select! { |advisory| advisory['fix_available'] } unless package['key']
          package['advisories'] = advisories
        end
        'tracked'
      end

      def enrich_javascripts(javascripts)
        source('npm') do
          npm = Sources::Npm.new(@http)
          latest = {}
          javascripts.map { |js| js['name'] }.uniq.each do |name|
            latest[name] = npm.latest(name)
          rescue Http::Error => e
            @errors << { 'source' => 'npm', 'message' => e.message }
          end
          javascripts.each { |js| js['latest'] = latest[js['name']] }
        end

        source('osv') do
          packages = javascripts.map { |js| [js['name'], js['version']] }.uniq
          osv = Sources::Osv.new(@http)
          found = osv.advisories(packages)
          javascripts.each { |js| js['advisories'] = found[[js['name'], js['version']]] || [] }
          osv.errors.each { |message| @errors << { 'source' => 'osv', 'message' => message } }
        end
      end

      def enrich_plugins(plugins)
        source('git') do
          heads = Sources::GitRemote.new.heads(plugins)
          plugins.each do |plugin|
            result = heads[plugin['name']]
            next unless result

            if result['remote_commit']
              plugin['remote_commit'] = result['remote_commit']
              plugin['up_to_date'] = result['remote_commit'] == plugin['commit']
            else
              plugin['remote_error'] = result['error']
            end
          end
        end
      end
    end
  end
end
