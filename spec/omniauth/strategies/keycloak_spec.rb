require 'spec_helper'

RSpec.describe OmniAuth::Strategies::KeycloakOpenId do
  let(:request) { double('Request', params: {}, cookies: {}, env: {}) }
  let(:app) do
    lambda do
      [200, {}, ['Hello.']]
    end
  end

  let(:config_body) {'{"issuer": "http://localhost:8080/auth/realms/example-realm",
  "authorization_endpoint": "http://localhost:8080/auth/realms/example-realm/protocol/openid-connect/auth",
  "token_endpoint": "http://localhost:8080/auth/realms/example-realm/protocol/openid-connect/token",
  "token_introspection_endpoint": "http://localhost:8080/auth/realms/example-realm/protocol/openid-connect/token/introspect",
  "userinfo_endpoint": "http://localhost:8080/auth/realms/example-realm/protocol/openid-connect/userinfo",
  "end_session_endpoint": "http://localhost:8080/auth/realms/example-realm/protocol/openid-connect/logout",
  "jwks_uri": "http://localhost:8080/auth/realms/example-realm/protocol/openid-connect/certs",
  "check_session_iframe": "http://localhost:8080/auth/realms/example-realm/protocol/openid-connect/login-status-iframe.html",
  "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "password", "client_credentials"],
  "response_types_supported": ["code", "none", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"],
  "subject_types_supported": ["public", "pairwise"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "userinfo_signing_alg_values_supported": ["RS256"],
  "request_object_signing_alg_values_supported": ["none", "RS256"],
  "response_modes_supported": ["query", "fragment", "form_post"],
  "registration_endpoint": "http://localhost:8080/auth/realms/example-realm/clients-registrations/openid-connect",
  "token_endpoint_auth_methods_supported": ["private_key_jwt", "client_secret_basic", "client_secret_post"],
  "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
  "claims_supported": ["sub", "iss", "auth_time", "name", "given_name", "family_name", "preferred_username", "email"],
  "claim_types_supported": ["normal"],
  "claims_parameter_supported": false,
  "scopes_supported": ["openid", "offline_access"],
  "request_parameter_supported": true,
  "request_uri_parameter_supported": true}'}

  let(:cert_body) {'{"keys": ["cert_key"]}'}

  subject do
    stub_request(:get, "http://localhost:8080/auth/realms/example-realm/.well-known/openid-configuration")
    .to_return(status: @config_error || 200, body: config_body, headers: {})
    stub_request(:get, "http://localhost:8080/auth/realms/example-realm/protocol/openid-connect/certs")
    .to_return(status: @cert_error || 200, body: cert_body, headers: {})

    @options = { client_options: { 'site' => @site || 'http://localhost:8080/', 'realm' => 'example-realm', 'raise_on_failure' => @raise_failure || false } }
    OmniAuth::Strategies::KeycloakOpenId.new(app, 'Example-Client', 'secret', @options).tap do |strategy|
      allow(strategy).to receive(:request) do
        request
      end
    end
  end

  before(:all) do
    OmniAuth.config.test_mode = true
  end

  after do
    OmniAuth.config.test_mode = false
  end

  describe 'client_options' do
    it 'should have the correct keycloak token url' do
      subject.setup_phase
      expect(subject.token_url).to eq('/auth/realms/example-realm/protocol/openid-connect/token')
    end

    it 'should have the correct keycloak authorization url' do
      subject.setup_phase
      expect(subject.authorize_url).to eq('/auth/realms/example-realm/protocol/openid-connect/auth')
    end
  end

  describe 'errors processing' do
    before(:each) do
      @raise_failure = true
    end

    context 'when site contains /auth part' do
      before(:each) do
        @site = 'http://localhost:8080/auth'
      end

      it 'raises Configuration Error' do
        expect{ subject.setup_phase }
          .to raise_error(OmniAuth::Strategies::KeycloakOpenId::ConfigurationError)
      end
    end

    context 'when openid configuration endpoint returns error response' do
      before(:each) do
        @config_error = 404
      end

      it 'raises Integration Error' do
        expect{ subject.setup_phase }
          .to raise_error(OmniAuth::Strategies::KeycloakOpenId::IntegrationError)
      end
    end

    context 'when certificates endpoint returns error response' do
      before(:each) do
        @cert_error = 404
      end

      it 'raises Integration Error' do
        expect{ subject.setup_phase }
          .to raise_error(OmniAuth::Strategies::KeycloakOpenId::IntegrationError)
      end
    end
  end
end
