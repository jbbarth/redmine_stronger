class CreateStrongerDependencyReports < ActiveRecord::Migration[7.2]
  def change
    create_table :stronger_dependency_reports do |t|
      t.string   :status, null: false, default: 'done', limit: 16
      t.datetime :requested_at
      t.datetime :collected_at
      t.float    :duration
      t.text     :data, limit: 16.megabytes
      t.string   :error, limit: 1000
    end

    add_index :stronger_dependency_reports, [:status, :collected_at]
  end
end
