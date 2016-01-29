class AddFeedTokenToUsers < ActiveRecord::Migration
  def up
    add_column :users, :feed_token, :string

    User.find_each do |user|
      user.update_attribute(:feed_token, SecureRandom.urlsafe_base64)
    end

    change_column :users, :feed_token, :string, null: false
  end

  def down
    remove_column :users, :feed_token
  end
end
