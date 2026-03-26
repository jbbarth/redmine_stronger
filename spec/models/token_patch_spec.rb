# frozen_string_literal: true

require "spec_helper"

describe Token do
  include ActiveSupport::Testing::TimeHelpers
  fixtures :users

  let(:user) { User.find_by_login("admin") }

  def create_api_token
    Token.where(user_id: user.id, action: 'api').delete_all
    Token.create!(user: user, action: 'api')
  end

  describe ".find_token — last_used_at tracking" do
    context "for an api token" do
      it "sets last_used_at when nil" do
        token = create_api_token
        freeze_time do
          Token.find_token('api', token.value)
          expect(token.reload.last_used_at).to be_within(1.second).of(Time.now)
        end
      end

      it "updates last_used_at when older than 1 minute" do
        token = create_api_token
        token.update_column(:last_used_at, 2.minutes.ago)
        freeze_time do
          Token.find_token('api', token.value)
          expect(token.reload.last_used_at).to be_within(1.second).of(Time.now)
        end
      end

      it "does not update last_used_at within the same minute" do
        token = create_api_token
        recent_time = 30.seconds.ago
        token.update_column(:last_used_at, recent_time)
        Token.find_token('api', token.value)
        expect(token.reload.last_used_at).to be_within(1.second).of(recent_time)
      end
    end

    context "for a non-api token" do
      it "does not touch last_used_at" do
        Token.where(user_id: user.id, action: 'feeds').delete_all
        token = Token.create!(user: user, action: 'feeds')
        Token.find_token('feeds', token.value)
        expect(token.reload.last_used_at).to be_nil
      end
    end
  end
end
