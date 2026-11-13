# frozen_string_literal: true

module RedmineStronger
  module DependencyAudit
    # Common severity scale for all advisory sources, most severe first.
    module Severity
      LEVELS = %w(critical high medium low negligible unknown).freeze
      ALERT  = %w(critical high).freeze

      # Same thresholds as bundler-audit.
      def self.from_cvss(score, v2: false)
        return 'unknown' if score.nil?

        score = score.to_f
        if v2
          if score >= 7.0 then 'high'
          elsif score >= 4.0 then 'medium'
          else 'low'
          end
        elsif score >= 9.0 then 'critical'
        elsif score >= 7.0 then 'high'
        elsif score >= 4.0 then 'medium'
        elsif score > 0 then 'low'
        else 'negligible'
        end
      end

      # GitHub / OSV labels (CRITICAL, HIGH, MODERATE, LOW) and Debian urgencies.
      def self.from_label(label)
        case label.to_s.downcase.delete('*').strip
        when 'critical' then 'critical'
        when 'high' then 'high'
        when 'moderate', 'medium' then 'medium'
        when 'low' then 'low'
        when 'unimportant', 'none' then 'negligible'
        else 'unknown'
        end
      end

      def self.rank(level)
        LEVELS.index(level) || LEVELS.size
      end

      def self.worst(advisories)
        Array(advisories).map { |a| a['severity'] }.min_by { |level| rank(level) }
      end
    end
  end
end
