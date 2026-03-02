class CreateUserLoginSessions < ActiveRecord::Migration[7.2]
  def change
    create_table :user_login_sessions do |t|
      t.integer  :user_id,     null: false
      t.datetime :logged_in_at, null: false
      t.string   :ip_address,   limit: 45    # IPv6 support
      t.string   :user_agent,   limit: 512
      t.string   :auth_method,  limit: 32    # 'password', 'cas', 'ldap', ...
      t.string   :os,           limit: 64
      t.string   :device_type,  limit: 16    # 'desktop', 'mobile', 'tablet'
    end

    add_index :user_login_sessions, [:user_id, :logged_in_at]
  end
end
