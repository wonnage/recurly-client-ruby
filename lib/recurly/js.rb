require 'openssl'

module Recurly
  # A collection of helper methods to use to verify
  # {Recurly.js}[http://js.recurly.com/] callbacks.
  module JS
    # Raised when signature verification fails.
    class RequestForgery < Error
    end

    # Raised when the timestamp is over an hour old. Prevents replay attacks.
    class RequestTooOld < RequestForgery
    end

    class << self
      # @return [String] A private key for Recurly.js.
      # @raise [ConfigurationError] No private key has been set.
      def private_key
        defined? @private_key and @private_key or raise(
          ConfigurationError, "private_key not configured"
        )
      end
      attr_writer :private_key

      # Create a signature for a given hash for Recurly.js
      # @param [Hash] Hash of data to sign as protected data
      def sign data
        data[:timestamp] ||= Time.now.to_i
        unsigned = to_query data
        signed = hash unsigned
        [signed, unsigned].join '|'
      end

      # Verify the signature string from Recurly.js and return the signed
      # attributes.
      # @param [String] Recurly.js signature to validate
      # @return [Hash] Data signed in the signature
      def verify! signature
        signature, data = signature.split '|'
        expected = hash data

        if signature != expected
          raise RequestForgery, <<EOE.chomp
Recurly.js signature forged or incorrect private key.
EOE
        end
        params = from_query data

        timestamp = params['timestamp']
        age = Time.now.to_i - timestamp.to_i
        if age > 3600 || age < -3600
          raise RequestTooOld, <<EOE.chomp
Timestamp is over an hour old. The server timezone may be incorrect or this \
may be a replay attack.
EOE
        end

        params
      end

      # @deprecated Use {.sign!} instead.
      # @return [String]
      def sign_subscription plan_code, account_code = nil
        sign(
          'account'      => { 'account_code' => account_code },
          'subscription' => { 'plan_code'    => plan_code }
        )
      end

      # @deprecated Use {.sign!} instead.
      # @return [String]
      def sign_billing_info account_code
        sign('account' => { 'account_code' => account_code })
      end

      # @deprecated Use {.sign!} instead.
      # @return [String]
      def sign_transaction(amount_in_cents, currency = nil, account_code = nil)
        sign(
          'account'     => { 'account_code' => account_code },
          'transaction' => {
            'amount_in_cents' => amount_in_cents,
            'currency'        => currency || Recurly.default_currency
          }
        )
      end

      # @deprecated Use {#validate_signature!} instead.
      # @return [true]
      # @raise [RequestForgery] If verification fails.
      def verify_subscription! params
        verify_signature! params[:signature]
      end

      # @deprecated Use {#validate_signature!} instead.
      # @return [true]
      # @raise [RequestForgery] If verification fails.
      def verify_billing_info! params
        verify_signature! params[:signature]
      end

      # @deprecated Use {#validate_signature!} instead.
      # @return [true]
      # @raise [RequestForgery] If verification fails.
      def verify_transaction! params
        verify_signature! params[:signature]
      end

      # @return [String]
      def inspect
        'Recurly.js'
      end

      private

      def to_query object, key = nil
        case object
        when Hash
          object.map { |k, v| to_query v, key ? "#{key}[#{k}]" : k }.sort * '&'
        when Array
          object.map { |o| to_query o, "#{key}[]" } * '&'
        else
          "#{CGI.escape key.to_s}=#{CGI.escape object.to_s}"
        end
      end

      def hash data
        OpenSSL::HMAC.hexdigest 'sha1', private_key, data
      end

      def from_query string
        string.scan(/([^=&]+)=([^=&]+)/).inject({}) do |hash, pair|
          key, value = pair.map(&CGI.method(:unescape))
          keypath, array = key.scan(/[^\[\]]+/), key[/\[\]$/]
          keypath.inject(hash) do |nest, component|
            next nest[component] ||= {} unless keypath.last == component
            array ? (nest[component] ||= []) << value : nest[component] = value
          end
          hash
        end
      end
    end
  end
end
