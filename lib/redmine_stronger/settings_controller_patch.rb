# frozen_string_literal: true

module RedmineStronger
  module SettingsControllerPatch
    # Refuses to turn the attachment scan on while clamd does not answer
    def plugin
      settings = params[:settings]
      if request.post? && params[:id] == 'redmine_stronger' && settings &&
         settings[:malware_scan] == '1' && Setting['plugin_redmine_stronger']['malware_scan'] != '1'
        socket = settings[:clamd_socket].presence || RedmineStronger::MalwareScanner.socket_path
        unless RedmineStronger::MalwareScanner.available?(socket: socket)
          flash[:error] = l(:stronger_error_clamd_unreachable, socket: socket)
          redirect_to plugin_settings_path(params[:id])
          return
        end
      end
      super
    end
  end
end

SettingsController.prepend RedmineStronger::SettingsControllerPatch
