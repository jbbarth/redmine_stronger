# frozen_string_literal: true

module RedmineStronger
  module DependencyAudit
    module Sources
      # Latest JavaScript library versions from the npm registry.
      class Npm
        URL = 'https://registry.npmjs.org/%s/latest'

        def initialize(http)
          @http = http
        end

        def latest(name)
          @http.get_json(format(URL, name.sub('/', '%2F')))['version']
        end
      end
    end
  end
end
