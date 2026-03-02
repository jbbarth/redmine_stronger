Deface::Override.new(
  virtual_path: 'my/account',
  name:         'add-login-sessions-section',
  insert_before: "erb[silent]:contains('content_for :sidebar')",
  text: <<~ERB
    <%= render partial: 'redmine_stronger/login_sessions/list',
               locals: { sessions: UserLoginSession.for_display(@user), show_title: true } %>
  ERB
)
