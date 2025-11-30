# name: discourse-polkadot-auth
# about: Authentication provider for Polkadot
# version: 0.1
# authors: Karim Jedda
# url: https://github.com/KarimJedda/discourse-polkadot-auth


# frozen_string_literal: true

require 'erb'
require_relative 'lib/polkadot_signature_verifier'

enabled_site_setting :polkadot_authentication_enabled

module ::OmniAuth
  module Strategies
    class Polkadot
      include ::OmniAuth::Strategy

      FIELDS = %w[
        uid
        name
        email
        email_verified
        nickname
        first_name
        last_name
        location
        description
        image
        groups
      ]

      COOKIE = "polkadot-auth-defaults"
      CHALLENGE_EXPIRATION_SECONDS = 300 # 5 minutes

      def request_phase
        if (env["REQUEST_METHOD"] == "POST") && (request.params["signature"])
          # Handle Polkadot wallet signature authentication
          signature = request.params["signature"]
          challenge = request.params["challenge"]
          address = request.params["address"]

          # Validate required parameters
          if signature.blank? || challenge.blank? || address.blank?
            return fail!(:missing_parameters)
          end

          # Validate challenge from session (prevents replay attacks)
          stored_challenge = session[:polkadot_challenge]
          stored_challenge_at = session[:polkadot_challenge_at]

          # Check challenge matches
          unless stored_challenge.present? && challenge == stored_challenge
            Rails.logger.warn "[PolkadotAuth] Challenge mismatch or missing from session"
            return fail!(:invalid_challenge)
          end

          # Check challenge hasn't expired
          if stored_challenge_at.blank? || (Time.now.to_i - stored_challenge_at) > CHALLENGE_EXPIRATION_SECONDS
            Rails.logger.warn "[PolkadotAuth] Challenge expired"
            session.delete(:polkadot_challenge)
            session.delete(:polkadot_challenge_at)
            return fail!(:challenge_expired)
          end

          # Clear challenge from session (prevents reuse)
          session.delete(:polkadot_challenge)
          session.delete(:polkadot_challenge_at)

          # Verify the signature
          # Note: Polkadot.js Extension wraps messages in <Bytes>...</Bytes> tags
          wrapped_challenge = "<Bytes>#{challenge}</Bytes>"
          is_valid = PolkadotSignatureVerifier.verify(
            address: address,
            signature: signature,
            message: wrapped_challenge
          )

          unless is_valid
            Rails.logger.warn "[PolkadotAuth] Signature verification failed for address: #{address}"
            return fail!(:invalid_signature)
          end

          Rails.logger.info "[PolkadotAuth] Signature verified successfully for address: #{address}"

          # Use the actual wallet address as the user identifier
          data = {
            "uid" => address,
            "name" => address,
            "email" => "#{address}@dot.li",
            "email_verified" => "true",
            "nickname" => address  # Full SS58 address as username
          }

          r = Rack::Response.new
          r.set_cookie(COOKIE, { value: data.to_json, path: "/", expires: 1.month.from_now })

          uri = URI.parse(callback_path)
          uri.query = URI.encode_www_form(data)
          r.redirect(uri.to_s)

          return r.finish
        end

        build_polkadot_form
      end

      def build_polkadot_form
        token =
          begin
            verifier = CSRFTokenVerifier.new
            verifier.call(env)
            verifier.form_authenticity_token
          end

        # Generate random challenge string
        challenge = SecureRandom.hex(32)

        # Store challenge in session with timestamp
        session[:polkadot_challenge] = challenge
        session[:polkadot_challenge_at] = Time.now.to_i

        # Render the external template
        render_polkadot_template(token, challenge)
      end

      private

      def render_polkadot_template(token, challenge)
        # Create a simple response with the rendered template
        template_path = File.expand_path("../app/views/polkadot_auth/form.html.erb", __FILE__)
        template_content = File.read(template_path)
        
        # Set instance variables for the template
        @token = token
        @challenge = challenge
        @nonce = SecureRandom.base64(32) # Generate CSP nonce
        
        # Render the ERB template
        erb = ERB.new(template_content)
        rendered_html = erb.result(binding)
        
        # Return as a Rack response array with CSP header (including WASM support for Polkadot)
        csp_header = "script-src 'strict-dynamic' 'nonce-#{@nonce}' 'wasm-unsafe-eval' https: 'unsafe-inline'"
        [200, {
          'Content-Type' => 'text/html',
          'Content-Security-Policy' => csp_header
        }, [rendered_html]]
      end

      def callback_phase
        super
      end

      def auth_hash
        info = request.params.slice(*FIELDS)
        uid = info.delete("uid")
        email_verified = (info.delete("email_verified") == "true")
        groups =
          info
            .delete("groups")
            &.split(",")
            &.map do |g|
              id, name = g.split(":", 2)
              { id: id, name: name }
            end
        OmniAuth::Utils.deep_merge(
          super,
          {
            "uid" => uid,
            "info" => info,
            "extra" => {
              "raw_info" => {
                "email_verified" => email_verified,
              },
              "raw_groups" => groups,
            },
          },
        )
      end
    end
  end
end

class PolkadotAuthenticator < Auth::ManagedAuthenticator
  def name
    "polkadotauth"
  end

  def can_revoke?
    true
  end

  def can_connect_existing_user?
    true
  end

  def enabled?
    SiteSetting.polkadot_authentication_enabled
  end

  def register_middleware(omniauth)
    omniauth.provider :polkadot, name: :polkadotauth
  end

  def primary_email_verified?(auth)
    auth["extra"]["raw_info"]["email_verified"]
  end

  def after_authenticate(auth_token, existing_account: nil)
    result = super
    if provides_groups? && (groups = auth_token[:extra][:raw_groups])&.any?
      result.associated_groups = groups.map { |group| group.slice(:id, :name) }
    end
    result
  end

  def provides_groups?
    SiteSetting.polkadot_authentication_provides_groups
  end
end

auth_provider authenticator: PolkadotAuthenticator.new

### DiscourseConnect
after_initialize do
  module ::PolkadotAuth
    PLUGIN_NAME = "discourse-polkadot-auth"

    class Engine < ::Rails::Engine
      engine_name PLUGIN_NAME
      isolate_namespace ::PolkadotAuth
    end
  end

  require_relative "lib/polkadot_auth/discourse_connect_extension"
  require_relative "lib/polkadot_auth/enable_sso_validator_extension"

  class ::PolkadotAuth::FakeDiscourseConnectController < ::ApplicationController
    requires_plugin "discourse-polkadot-auth"

    skip_before_action :check_xhr,
                       :preload_json,
                       :redirect_to_login_if_required,
                       :verify_authenticity_token

    SIMPLE_FIELDS = %w[external_id email username name]
    ADVANCED_FIELDS = DiscourseConnectBase::ACCESSORS.map(&:to_s) - SIMPLE_FIELDS
    FIELDS = SIMPLE_FIELDS + ADVANCED_FIELDS

    BOOLS = DiscourseConnectBase::BOOLS.map(&:to_s)

    COOKIE = "polkadot-auth-discourseconnect-defaults"
    CHALLENGE_EXPIRATION_SECONDS = 300 # 5 minutes

    def custom_fields
      ::UserField
        .all
        .pluck(:id, :name)
        &.map { |id, name| { "#{name}": "custom.user_field_#{id}" } }
        &.reduce(:merge!) || {}
    end

    def auth
      Rails.logger.info "[PolkadotAuth] === AUTH METHOD CALLED ==="
      Rails.logger.info "[PolkadotAuth] Request method: #{request.method}"
      Rails.logger.info "[PolkadotAuth] All params: #{params.inspect}"
      
      params.require(:sso)
      @payload = request.query_string
      Rails.logger.info "[PolkadotAuth] Payload: #{@payload}"
      
      sso = DiscourseConnectBase.parse(@payload, SiteSetting.discourse_connect_secret)

      Rails.logger.info "[PolkadotAuth] Params external_id: #{params[:external_id]}"
      Rails.logger.info "[PolkadotAuth] SSO return_sso_url: #{sso.return_sso_url.inspect} (class: #{sso.return_sso_url.class})"

      if request.method == "POST" && (params[:external_id] || params[:signature])
        Rails.logger.info "[PolkadotAuth] Processing POST request"

        if params[:signature]
          # Handle Polkadot wallet authentication
          Rails.logger.info "[PolkadotAuth] Processing Polkadot signature authentication"
          signature = params[:signature]
          challenge = params[:challenge]
          address = params[:address]

          # Validate required parameters
          if signature.blank? || challenge.blank? || address.blank?
            Rails.logger.error "[PolkadotAuth] Missing required parameters"
            return redirect_to sso.return_sso_url, alert: "Missing required parameters"
          end

          # Validate challenge from session (prevents replay attacks)
          stored_challenge = session[:polkadot_challenge]
          stored_challenge_at = session[:polkadot_challenge_at]

          # Check challenge matches
          unless stored_challenge.present? && challenge == stored_challenge
            Rails.logger.warn "[PolkadotAuth] Challenge mismatch or missing from session"
            return redirect_to sso.return_sso_url, alert: "Invalid challenge"
          end

          # Check challenge hasn't expired
          if stored_challenge_at.blank? || (Time.now.to_i - stored_challenge_at) > CHALLENGE_EXPIRATION_SECONDS
            Rails.logger.warn "[PolkadotAuth] Challenge expired"
            session.delete(:polkadot_challenge)
            session.delete(:polkadot_challenge_at)
            return redirect_to sso.return_sso_url, alert: "Challenge expired, please try again"
          end

          # Clear challenge from session (prevents reuse)
          session.delete(:polkadot_challenge)
          session.delete(:polkadot_challenge_at)

          # Verify the signature
          # Note: Polkadot.js Extension wraps messages in <Bytes>...</Bytes> tags
          wrapped_challenge = "<Bytes>#{challenge}</Bytes>"
          is_valid = PolkadotSignatureVerifier.verify(
            address: address,
            signature: signature,
            message: wrapped_challenge
          )

          unless is_valid
            Rails.logger.warn "[PolkadotAuth] Signature verification failed for address: #{address}"
            return redirect_to sso.return_sso_url, alert: "Signature verification failed"
          end

          Rails.logger.info "[PolkadotAuth] Signature verified successfully for address: #{address}"

          # Use the actual wallet address as the user identifier
          sso.external_id = address
          sso.email = "#{address}@dot.li"
          sso.username = address  # Full SS58 address as username
          sso.name = address

          data = {
            "external_id" => sso.external_id,
            "email" => sso.email,
            "username" => sso.username,
            "name" => sso.name
          }
          cookies[COOKIE] = { value: data.to_json, path: "/", expires: 1.month.from_now }
        else
          # Handle traditional form authentication
          Rails.logger.info "[PolkadotAuth] Processing traditional form authentication with external_id"
          
          data = {}
          (FIELDS + custom_fields.values).each do |f|
            if field = f.to_s[/^custom\.(.+)$/, 1]
              sso.custom_fields[field] = params[f]
            else
              sso.send(:"#{f}=", params[f])
            end
            data[f] = params[f]
            cookies[COOKIE] = { value: data.to_json, path: "/", expires: 1.month.from_now }
          end
        end

        return_url_string = sso.return_sso_url.to_s
        Rails.logger.info "[PolkadotAuth] return_sso_url as string: #{return_url_string}"
        
        final_url = sso.to_url(return_url_string)
        Rails.logger.info "[PolkadotAuth] Final redirect URL: #{final_url}"
        Rails.logger.info "[PolkadotAuth] Final redirect URL class: #{final_url.class}"
        
        begin
          Rails.logger.info "[PolkadotAuth] About to redirect..."
          return redirect_to final_url
        rescue => e
          Rails.logger.error "[PolkadotAuth] Redirect failed: #{e.class}: #{e.message}"
          Rails.logger.error "[PolkadotAuth] Backtrace: #{e.backtrace.first(10).join("\n")}"
          raise e
        end
      end

      raw_defaults = cookies[COOKIE] || "{}"
      @defaults =
        begin
          JSON.parse(raw_defaults)
        rescue StandardError
          {}
        end
      @defaults["return_sso_url"] = sso.return_sso_url.to_s
      @defaults["nonce"] = sso.nonce
      @defaults["external_id"] = SecureRandom.hex(8) if @defaults["external_id"].blank?
      render_form
    end

    private

    def render_form
      @simple_fields = SIMPLE_FIELDS
      @advanced_fields = ADVANCED_FIELDS
      @custom_fields = custom_fields
      @bools = BOOLS

      # Generate and store challenge for Polkadot auth
      @challenge = SecureRandom.hex(32)
      session[:polkadot_challenge] = @challenge
      session[:polkadot_challenge_at] = Time.now.to_i

      append_view_path(File.expand_path("../app/views", __FILE__))
      render template: "fake_discourse_connect/form", layout: false
    end
  end

  PolkadotAuth::Engine.routes.draw do
    get "/fake-discourse-connect" => "fake_discourse_connect#auth"
    post "/fake-discourse-connect" => "fake_discourse_connect#auth"
  end

  Discourse::Application.routes.append { mount ::PolkadotAuth::Engine, at: "/polkadot-auth" }

  DiscourseConnect.singleton_class.prepend(PolkadotAuth::DiscourseConnectExtension)
  EnableSsoValidator.prepend(PolkadotAuth::EnableSsoValidatorExtension)
end
