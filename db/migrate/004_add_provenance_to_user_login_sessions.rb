class AddProvenanceToUserLoginSessions < ActiveRecord::Migration[7.2]
  def change
    add_column :user_login_sessions, :provenance, :string
  end
end
