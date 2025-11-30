# frozen_string_literal: true

module PolkadotAuth
  module EnableSsoValidatorExtension
    extend ActiveSupport::Concern

    def valid_value?(val)
      return true if SiteSetting.polkadot_authentication_enabled
      super
    end
  end
end
