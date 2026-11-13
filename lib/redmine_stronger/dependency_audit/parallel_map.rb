# frozen_string_literal: true

module RedmineStronger
  module DependencyAudit
    # Runs a block over items with a small pool of threads (network bound work).
    module ParallelMap
      def self.each(items, threads: 8)
        queue = Queue.new
        items.each { |item| queue << item }
        queue.close
        Array.new([threads, items.size].min) do
          Thread.new do
            while (item = queue.pop)
              yield(item)
            end
          end
        end.each(&:join)
      end
    end
  end
end
