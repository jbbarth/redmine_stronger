# frozen_string_literal: true

module RedmineStronger
  module DependencyAudit
    # Debian package version comparison (dpkg --compare-versions),
    # without spawning dpkg for each of the many comparisons.
    module DebianVersion
      def self.compare(a, b)
        ea, ua, ra = split(a)
        eb, ub, rb = split(b)
        result = ea <=> eb
        result = compare_part(ua, ub) if result.zero?
        result = compare_part(ra, rb) if result.zero?
        result
      end

      def self.split(version)
        version = version.to_s.strip
        epoch, rest = version.include?(':') ? version.split(':', 2) : ['0', version]
        upstream, _, revision = rest.rpartition('-')
        upstream, revision = revision, '' if upstream.empty?
        [epoch.to_i, upstream, revision]
      end

      def self.compare_part(a, b)
        a = a.dup
        b = b.dup
        until a.empty? && b.empty?
          na = a.slice!(/\A\D*/)
          nb = b.slice!(/\A\D*/)
          result = compare_lexical(na, nb)
          return result unless result.zero?

          da = a.slice!(/\A\d*/)
          db = b.slice!(/\A\d*/)
          result = da.to_i <=> db.to_i
          return result unless result.zero?
        end
        0
      end

      # Letters sort before non-letters, and "~" before everything, even the end.
      def self.compare_lexical(a, b)
        [a.size, b.size].max.times do |i|
          result = order(a[i]) <=> order(b[i])
          return result unless result.zero?
        end
        0
      end

      def self.order(char)
        if char.nil? then 0
        elsif char == '~' then -1
        elsif char.match?(/[A-Za-z]/) then char.ord
        else char.ord + 256
        end
      end
    end
  end
end
