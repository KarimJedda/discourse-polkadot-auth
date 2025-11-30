# frozen_string_literal: true

module PolkadotAuth
  module DiscourseConnectExtension
    extend ActiveSupport::Concern

    def sso_url
      if SiteSetting.polkadot_authentication_enabled
        return "#{Discourse.base_path}/polkadot-auth/fake-discourse-connect"
      end
      super
    end
  end
end
