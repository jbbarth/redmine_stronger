Deface::Override.new(
  virtual_path:  'settings/_api',
  name:          'stronger-api-tab-hint',
  insert_after:  'div.box.tabular.settings',
  text: <<~ERB
    <p class="icon icon-help">
      <%= l(:stronger_api_tab_hint_html,
            link: link_to(l(:stronger_api_tab_hint_link),
                          plugin_settings_path(id: 'redmine_stronger'))).html_safe %>
    </p>
  ERB
)
