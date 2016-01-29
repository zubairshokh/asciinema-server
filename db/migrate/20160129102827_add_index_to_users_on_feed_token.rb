class AddIndexToUsersOnFeedToken < ActiveRecord::Migration
  def change
    add_index :users, :feed_token
  end
end
