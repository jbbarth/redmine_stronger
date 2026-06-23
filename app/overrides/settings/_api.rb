Deface::Override.new(
  virtual_path:  'settings/_api',
  name:          'stronger-api-tab-hint',
  insert_after:  "erb[loud]:contains('submit_tag')",
  text: <<~ERB
    <p class="stronger-api-hint">
      <%= l(:stronger_api_tab_hint_html,
            link: link_to(l(:stronger_api_tab_hint_link),
                          plugin_settings_path(id: 'redmine_stronger'))).html_safe %>
    </p>
  ERB
)
