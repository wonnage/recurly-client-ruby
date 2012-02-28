require 'openssl'
require 'recurly/js/deprecated_methods'

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
        signed = digest unsigned
        [signed, unsigned].join '|'
      end

      # Verify the signature string from Recurly.js and return the signed
      # attributes.
      # @param [String] Recurly.js signature to validate
      # @return [Hash] Data signed in the signature
      def verify! signature
        signature, data = signature.split '|'
        expected = digest data

        if signature != expected
          raise RequestForgery, <<EOE.chomp
Recurly.js signature forged or incorrect private key.
EOE
        end
        params = from_query data

        age = Time.now.to_i - params['timestamp'].to_i
        if age > 3600 || age < -3600
          raise RequestTooOld, <<EOE.chomp
Timestamp is over an hour old. The server timezone may be incorrect or this \
may be a replay attack.
EOE
        end

        params
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

      def digest string
        OpenSSL::HMAC.hexdigest 'sha1', private_key, string
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
