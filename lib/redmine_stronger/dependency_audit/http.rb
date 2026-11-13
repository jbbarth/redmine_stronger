# frozen_string_literal: true

require 'net/http'
require 'json'

module RedmineStronger
  module DependencyAudit
    # Minimal HTTP client for the dependency audit collector.
    # Uses the proxy from the environment (https_proxy, no_proxy), including
    # its credentials, which Net::HTTP does not always pick up on its own.
    class Http
      class Error < StandardError; end
      # Timeout, dropped connection or server error: worth another attempt.
      class TransientError < Error; end

      USER_AGENT    = 'redmine_stronger-dependency-audit'
      MAX_REDIRECTS = 3
      TRANSIENT_ERRORS = [Net::OpenTimeout, Net::ReadTimeout, Errno::ECONNRESET, Errno::ECONNREFUSED,
                          EOFError].freeze

      def initialize(open_timeout: 10, read_timeout: 30, attempts: 2, retry_delay: 3, max_bytes: 200 * 1024 * 1024)
        @open_timeout = open_timeout
        @read_timeout = read_timeout
        @attempts     = attempts
        @retry_delay  = retry_delay
        @max_bytes    = max_bytes
      end

      def get(url, headers = {})
        with_retry { request(URI(url), Net::HTTP::Get, headers) }
      end

      def get_json(url, headers = {})
        JSON.parse(get(url, { 'Accept' => 'application/json' }.merge(headers)))
      end

      def post_json(url, payload)
        body = JSON.generate(payload)
        # Only read-only queries are posted (OSV), so they can be retried.
        JSON.parse(with_retry { request(URI(url), Net::HTTP::Post, { 'Content-Type' => 'application/json' }, body) })
      end

      private

      def with_retry
        attempt = 0
        begin
          attempt += 1
          yield
        rescue TransientError
          raise if attempt >= @attempts

          sleep @retry_delay
          retry
        end
      end

      def request(uri, klass, headers, body = nil, redirects = 0)
        http = connection(uri)
        req = klass.new(uri)
        req['User-Agent'] = USER_AGENT
        headers.each { |k, v| req[k] = v }
        req.body = body if body

        http.start do
          http.request(req) do |response|
            case response
            when Net::HTTPSuccess
              return read_limited(response, uri)
            when Net::HTTPRedirection
              raise Error, "too many redirects for #{uri}" if redirects >= MAX_REDIRECTS

              return request(URI.join(uri, response['location']), klass, headers, body, redirects + 1)
            when Net::HTTPServerError, Net::HTTPTooManyRequests
              raise TransientError, "HTTP #{response.code} for #{uri}"
            else
              raise Error, "HTTP #{response.code} for #{uri}"
            end
          end
        end
      rescue Error
        raise
      rescue *TRANSIENT_ERRORS => e
        raise TransientError, "#{e.class}: #{e.message} (#{uri})"
      rescue StandardError => e
        raise Error, "#{e.class}: #{e.message} (#{uri})"
      end

      def connection(uri)
        proxy = uri.find_proxy
        http =
          if proxy
            Net::HTTP.new(uri.host, uri.port, proxy.host, proxy.port,
                          proxy.user && URI.decode_www_form_component(proxy.user),
                          proxy.password && URI.decode_www_form_component(proxy.password))
          else
            Net::HTTP.new(uri.host, uri.port, nil)
          end
        http.use_ssl      = uri.scheme == 'https'
        http.open_timeout = @open_timeout
        http.read_timeout = @read_timeout
        http
      end

      def read_limited(response, uri)
        buffer = String.new(capacity: 64 * 1024)
        response.read_body do |chunk|
          buffer << chunk
          raise Error, "response larger than #{@max_bytes} bytes (#{uri})" if buffer.bytesize > @max_bytes
        end
        buffer
      end
    end
  end
end
