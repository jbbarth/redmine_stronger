class AddLockCommentToUsers < ActiveRecord::Migration[4.2]
  def self.up
    add_column :users, :lock_comment, :text
  end

  def self.down
    remove_column :users, :lock_comment
  end
end
