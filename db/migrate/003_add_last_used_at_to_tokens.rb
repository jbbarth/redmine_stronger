class AddLastUsedAtToTokens < ActiveRecord::Migration[7.2]
  def change
    add_column :tokens, :last_used_at, :datetime
  end
end
