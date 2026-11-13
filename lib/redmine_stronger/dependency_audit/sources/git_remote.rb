# frozen_string_literal: true

require 'open3'

module RedmineStronger
  module DependencyAudit
    module Sources
      # Upstream head of each plugin repository (git ls-remote, https only).
      class GitRemote
        TIMEOUT = 30

        def initialize(threads: 8)
          @threads = threads
        end

        # plugins: inventory items => { name => { 'remote_commit' => sha } or { 'error' => msg } }
        def heads(plugins)
          results = {}
          mutex = Mutex.new
          candidates = plugins.select { |p| p['remote'].present? && p['commit'].present? }
          ParallelMap.each(candidates, threads: @threads) do |plugin|
            result = ls_remote(plugin['remote'], plugin['branch'])
            mutex.synchronize { results[plugin['name']] = result }
          end
          results
        end

        def ls_remote(url, branch)
          ref = branch.present? && branch != 'HEAD' ? "refs/heads/#{branch}" : 'HEAD'
          env = { 'GIT_TERMINAL_PROMPT' => '0', 'GIT_ASKPASS' => 'true', 'LC_ALL' => 'C' }
          Open3.popen3(env, 'git', 'ls-remote', url, ref) do |stdin, stdout, stderr, wait|
            stdin.close
            unless wait.join(TIMEOUT)
              Process.kill('KILL', wait.pid)
              return { 'error' => "git ls-remote timed out after #{TIMEOUT}s" }
            end
            return { 'error' => stderr.read.to_s.lines.last.to_s.strip.presence || 'git ls-remote failed' } unless wait.value.success?

            sha = stdout.read.to_s[/\A\h{40}/]
            sha ? { 'remote_commit' => sha } : { 'error' => "#{ref} not found" }
          end
        rescue SystemCallError => e
          { 'error' => e.message }
        end
      end
    end
  end
end
