class AddOutcomeToUserLoginSessions < ActiveRecord::Migration[7.2]
  def change
    add_column :user_login_sessions, :outcome, :string, limit: 16, default: 'success', null: false
  end
end
