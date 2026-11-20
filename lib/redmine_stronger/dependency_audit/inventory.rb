# frozen_string_literal: true

require 'open3'

module RedmineStronger
  module DependencyAudit
    # Everything that can be learned locally, without any network access.
    # Items are plain hashes with string keys, stored as is in the snapshot.
    class Inventory
      # Source packages always listed, even without known vulnerability:
      # the system components Redmine relies on.
      KEY_SOURCE_PACKAGES = %w(
        openssl openssh glibc zlib curl ca-certificates sudo
        libxml2 libxslt libyaml
        imagemagick ghostscript poppler pandoc
        git subversion mercurial cvs bzr darcs
        clamav apache2 nginx
        mariadb mysql-8.0 sqlite3
      ).freeze
      KEY_SOURCE_PACKAGE_PATTERNS = [/\Apostgresql-\d+\z/, /\Aruby\d\.\d+\z/, /\Alinux\z/].freeze

      # A banner only counts at the start of a comment (/*!, /**, @license),
      # not when a library mentions another one ("requires jQuery v1.2.3").
      BANNER_START = %r{/\*[!*]?[\s*]*(?:@license\s+)?}

      # Known vendored JavaScript libraries: npm name and version pattern
      # found in the file banner (or file head, or file name).
      JAVASCRIPT_LIBRARIES = [
        { npm: 'jquery',               banner: /jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)/ },
        { npm: 'jquery-ui',            banner: /jQuery UI - v(\d+\.\d+\.\d+)/ },
        { npm: 'tinymce',              banner: /TinyMCE version (\d+\.\d+\.\d+)/ },
        { npm: 'tinymce',              head: %r{\A// (\d+\.\d+\.\d+) \(} },
        { npm: 'select2',              banner: /Select2 (\d+\.\d+\.\d+)/ },
        { npm: 'intro.js',             banner: /Intro\.js v(\d+\.\d+\.\d+)/ },
        { npm: 'chart.js',             banner: /Chart\.js v(\d+\.\d+\.\d+)/ },
        { npm: 'tablesort',            banner: /tablesort v(\d+\.\d+\.\d+)/ },
        { npm: 'angular',              banner: /AngularJS v(\d+\.\d+\.\d+)/ },
        { npm: 'angular-hotkeys',      banner: /angular-hotkeys v(\d+\.\d+\.\d+)/ },
        { npm: 'angular-ui-bootstrap', file: /ui-bootstrap-tpls-(\d+\.\d+\.\d+)/ },
        { npm: 'timeago',              banner: /Timeago is a jQuery plugin.*?@version v?(\d+\.\d+\.\d+)/m },
        { npm: 'dompurify',            banner: /DOMPurify (\d+\.\d+\.\d+)/ },
        { npm: 'mermaid',              banner: /mermaid v?(\d+\.\d+\.\d+)/ }
      ].map do |lib|
        lib[:banner] ? lib.merge(banner: Regexp.new(BANNER_START.source + lib[:banner].source, lib[:banner].options)) : lib
      end.freeze

      # Only the head of each file is searched, except for bundles
      # (several libraries concatenated in one file, such as Redmine's jQuery + jQuery UI).
      JAVASCRIPT_HEAD_BYTES   = 4096
      JAVASCRIPT_BUNDLE_BYTES = 2 * 1024 * 1024
      JAVASCRIPT_MAX_FILES    = 5000
      # Propshaft digested copies (name-1a2b3c4d.js) duplicate the original file.
      DIGESTED_FILE = /-\h{8}\.js\z/

      def initialize(root: Rails.root)
        @root = Pathname.new(root)
      end

      def environment
        [os, ruby, rails, redmine, database].compact
      end

      def os_release
        @os_release ||= begin
          path = Pathname.new('/etc/os-release')
          path.readable? ? parse_os_release(path.read) : {}
        end
      end

      def parse_os_release(content)
        content.each_line.with_object({}) do |line, hash|
          key, value = line.strip.split('=', 2)
          next if key.blank? || value.nil? || key.start_with?('#')

          hash[key.downcase] = value.delete_prefix('"').delete_suffix('"')
        end
      end

      def os
        info = os_release
        return if info.empty?

        {
          'kind' => 'os', 'name' => info['pretty_name'] || info['name'],
          'product' => info['id'], 'version' => os_point_release(info),
          'codename' => info['version_codename']
        }
      end

      # VERSION_ID only holds the release (11, 24.04): the point release
      # (11.11, 24.04.5) comes from /etc/debian_version or VERSION.
      def os_point_release(info, debian_version_path: '/etc/debian_version')
        release = info['version_id'].to_s
        point =
          if info['id'] == 'debian' && File.readable?(debian_version_path)
            File.read(debian_version_path).strip
          else
            info['version'].to_s[/\A\d+(\.\d+)+/]
          end
        point.to_s.start_with?("#{release}.") ? point : release
      end

      def ruby
        { 'kind' => 'ruby', 'name' => "Ruby (#{RUBY_ENGINE})", 'product' => 'ruby',
          'version' => RUBY_VERSION, 'engine' => RUBY_ENGINE }
      end

      def rails
        { 'kind' => 'rails', 'name' => 'Ruby on Rails', 'product' => 'rails', 'version' => Rails.version }
      end

      def redmine
        version = [Redmine::VERSION::MAJOR, Redmine::VERSION::MINOR, Redmine::VERSION::TINY].join('.')
        { 'kind' => 'redmine', 'name' => 'Redmine', 'product' => 'redmine', 'version' => version,
          'branch' => Redmine::VERSION::BRANCH.to_s }
      end

      def database
        connection = ActiveRecord::Base.connection
        case connection.adapter_name
        when /postg/i
          raw = connection.select_value('SHOW server_version')
          { 'kind' => 'database', 'name' => 'PostgreSQL', 'product' => 'postgresql',
            'version' => raw.to_s[/\A\d+(\.\d+)*/], 'raw_version' => raw }
        when /mysql|trilogy/i
          raw = connection.select_value('SELECT VERSION()').to_s
          mariadb = raw.match?(/mariadb/i)
          { 'kind' => 'database', 'name' => mariadb ? 'MariaDB' : 'MySQL',
            'product' => mariadb ? 'mariadb' : 'mysql',
            'version' => raw[/\A\d+(\.\d+)*/], 'raw_version' => raw }
        when /sqlite/i
          { 'kind' => 'database', 'name' => 'SQLite', 'product' => nil,
            'version' => connection.select_value('SELECT sqlite_version()') }
        when /sqlserver/i
          { 'kind' => 'database', 'name' => 'SQL Server', 'product' => 'mssqlserver',
            'version' => connection.select_value("SELECT SERVERPROPERTY('ProductVersion')").to_s }
        end
      end

      DEVELOPMENT_GROUPS = [:development, :test].freeze

      # Gems of every installed group (optional ones such as ldap or
      # minimagick included), except the development and test tooling
      # of the other environments.
      def gems
        definition = Bundler.definition
        skipped = (DEVELOPMENT_GROUPS - [Rails.env.to_sym]) + Array(Bundler.settings[:without]).map(&:to_sym)
        groups = definition.groups - skipped
        direct = definition.dependencies
                           .select { |dep| dep.groups.intersect?(groups) }
                           .to_set(&:name)
        specs = begin
          definition.specs_for(groups)
        rescue StandardError
          Bundler.load.specs
        end

        items = specs.map do |spec|
          {
            'kind' => 'gem', 'name' => spec.name, 'version' => spec.version.to_s,
            'platform' => spec.platform.to_s, 'direct' => direct.include?(spec.name),
            'rubygems' => spec.source.is_a?(Bundler::Source::Rubygems)
          }
        end
        items.uniq { |g| g['name'] }.sort_by { |g| g['name'] }
      end

      # Installed dpkg packages, grouped by source package.
      # Empty when the system is not Debian based.
      def packages
        out, status = capture('dpkg-query', '-W', '-f',
                              "${binary:Package}\\t${source:Package}\\t${Version}\\t${source:Version}\\t${db:Status-Abbrev}\\n")
        return [] unless status

        rows = out.each_line.map { |line| line.chomp.split("\t") }
                  .select { |row| row.size >= 5 && row[4].start_with?('ii') }
        by_source = rows.group_by { |row| row[1] }
        candidates = apt_candidates(by_source.select { |source, _| key_source_package?(source) }
                                             .values.flatten(1).map(&:first))

        items = by_source.map do |source, binaries|
          {
            'kind' => 'package', 'name' => source, 'version' => binaries.first[3],
            'binaries' => binaries.map(&:first).sort,
            'key' => key_source_package?(source),
            'candidate' => binaries.filter_map { |row| candidates[row[0]] }
                                   .find { |candidate| candidate != binaries.first[2] }
          }
        end
        items.sort_by { |p| p['name'] }
      end

      def key_source_package?(source)
        KEY_SOURCE_PACKAGES.include?(source) || KEY_SOURCE_PACKAGE_PATTERNS.any? { |re| re.match?(source) }
      end

      # Upgrade candidates from the local apt lists (as fresh as the last apt update).
      def apt_candidates(binaries)
        return {} if binaries.empty?

        out, status = capture('apt-cache', 'policy', *binaries)
        return {} unless status

        parse_apt_policy(out)
      end

      def parse_apt_policy(output)
        result = {}
        current = installed = nil
        output.each_line do |line|
          if line =~ /\A(\S+):\s*\z/
            current = Regexp.last_match(1)
            installed = nil
          elsif current && line =~ /\A\s+Installed\s*: (\S+)/
            installed = Regexp.last_match(1) unless Regexp.last_match(1) == '(none)'
          elsif current && line =~ /\A\s+Candidate\s*: (\S+)/
            candidate = Regexp.last_match(1)
            result[current] = candidate if candidate != '(none)' && installed
          end
        end
        result
      end

      # Vendored JavaScript libraries (core and plugins), plus npm pins
      # declared in importmap files.
      def javascripts
        found = javascript_files.flat_map { |path| scan_javascript(path) }
        found.concat(importmap_pins)
        found.uniq { |js| [js['name'], js['version'], js['path']] }
             .sort_by { |js| [js['name'], js['path']] }
      end

      def javascript_files
        dirs = [@root.join('vendor/javascript'), @root.join('app/assets/javascripts'), @root.join('public/javascripts')]
        Redmine::Plugin.all.each do |plugin|
          dirs << Pathname.new(plugin.directory).join('assets/javascripts')
          dirs << Pathname.new(plugin.directory).join('app/assets/javascripts')
        end
        dirs.select(&:directory?)
            .flat_map { |dir| Dir.glob(dir.join('**/*.js').to_s) }
            .reject { |path| path.include?('/node_modules/') || DIGESTED_FILE.match?(path) }
            .first(JAVASCRIPT_MAX_FILES)
      end

      def scan_javascript(path)
        head = File.binread(path, JAVASCRIPT_HEAD_BYTES).to_s.scrub
        bundle = nil
        JAVASCRIPT_LIBRARIES.filter_map do |lib|
          version =
            if lib[:file]
              File.basename(path)[lib[:file], 1]
            elsif lib[:head]
              head[lib[:head], 1]
            else
              match = lib[:banner].match(head)
              if match.nil? && head.include?('/*!') && File.size(path) <= JAVASCRIPT_BUNDLE_BYTES
                bundle ||= File.binread(path).scrub
                match = banner_in_bundle(lib[:banner], bundle)
              end
              match && match.captures.compact.first
            end
          next unless version

          { 'kind' => 'javascript', 'name' => lib[:npm], 'version' => version, 'path' => relative(path) }
        end
      rescue SystemCallError
        []
      end

      # In a bundle, only banners in license comments count, not strings in code.
      def banner_in_bundle(pattern, content)
        content.scan(%r{/\*!.{0,200}}m) do
          match = pattern.match(Regexp.last_match(0))
          return match if match
        end
        nil
      end

      def importmap_pins
        files = [@root.join('config/importmap.rb')]
        Redmine::Plugin.all.each { |plugin| files << Pathname.new(plugin.directory).join('config/importmap.rb') }
        files.select(&:file?).flat_map do |file|
          file.read.scan(/^\s*pin\s+["']([^"']+)["'].*#\s*@(\d+\.\d+\.\d+\S*)/).map do |name, version|
            { 'kind' => 'javascript', 'name' => name, 'version' => version, 'path' => relative(file.to_s) }
          end
        end
      end

      def plugins
        Redmine::Plugin.all.map do |plugin|
          dir = plugin.directory.to_s
          item = { 'kind' => 'plugin', 'name' => plugin.id.to_s, 'label' => plugin.name.to_s,
                   'version' => plugin.version.to_s, 'path' => relative(dir) }
          head, = capture('git', '-C', dir, 'rev-parse', 'HEAD')
          if head.present?
            date, = capture('git', '-C', dir, 'log', '-1', '--format=%cI')
            branch, = capture('git', '-C', dir, 'rev-parse', '--abbrev-ref', 'HEAD')
            remote, = capture('git', '-C', dir, 'config', '--get', 'remote.origin.url')
            item.merge!('commit' => head.strip, 'commit_date' => date.to_s.strip.presence,
                        'branch' => branch.to_s.strip.presence, 'remote' => public_remote(remote.to_s.strip))
          end
          item
        end
      end

      # Number of local commits on top of an upstream commit, or nil when that
      # commit is unknown locally or not an ancestor of HEAD (behind or diverged).
      def commits_ahead(path, commit)
        dir = @root.join(path).to_s
        _, ancestor = capture('git', '-C', dir, 'merge-base', '--is-ancestor', commit, 'HEAD')
        return unless ancestor

        count, = capture('git', '-C', dir, 'rev-list', '--count', "#{commit}..HEAD")
        count.to_s.strip.presence&.to_i
      end

      # git@github.com:owner/repo.git => https://github.com/owner/repo.git
      # Credentials are dropped. Non-https remotes are not queried.
      def public_remote(url)
        return if url.blank?

        url = "https://#{Regexp.last_match(1)}/#{Regexp.last_match(2)}" if url =~ /\A[\w.-]+@([\w.-]+):(.+)\z/
        uri = URI.parse(url)
        return unless uri.is_a?(URI::HTTPS)

        uri.user = nil
        uri.password = nil
        uri.to_s
      rescue URI::InvalidURIError
        nil
      end

      private

      def relative(path)
        Pathname.new(path).relative_path_from(@root).to_s
      rescue ArgumentError
        path.to_s
      end

      def capture(*command)
        out, status = Open3.capture2({ 'LC_ALL' => 'C' }, *command, err: File::NULL)
        [out, status.success?]
      rescue SystemCallError
        [nil, false]
      end
    end
  end
end
