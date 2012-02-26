require 'openssl'
require 'addressable/uri'

module Recurly
  # A collection of helper methods to use to verify
  # {Recurly.js}[http://js.recurly.com/] callbacks.
  module JS
    # Raised when signature verification fails.
    class RequestForgery < Error
    end

    # Raised when the timestamp is over an hour old. Prevents replay attacks.
    class RequestTooOldError < RequestForgery
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
      def generate_signature(data_to_protect)
        data_string = convert_to_query_string(data_to_protect)
        signature = hash(data_string)
        [signature, data_string].join "|"
      end

      # Validate the signature string from Recurly.js and return the signed attributes.
      # @param [String] Recurly.js signature to validate
      # @return [Hash] Data signed in the signature
      def validate_signature! signature_with_data
        signature, data_string = signature_with_data.split('|', 2)
        expected_signature = hash(data_string)

        raise RequestForgery.new "Recurly.js signature forged or incorrect private key" if signature != expected_signature

        address = Addressable::URI.new
        address.query = data_string
        data_hash = address.query_values

        if data_hash['timestamp'] && (time_difference(data_hash['timestamp']) > 3600)
          raise RequestTooOldError.new "Timestamp is over an hour old. The server timezone may be incorrect or this may be a replay attack."
        end

        data_hash
      end

      # @deprecated Use {#generate_signature} instead.
      # @return [String]
      def sign_subscription plan_code, account_code = nil
        generate_signature({
          'account' => {
            'account_code' => account_code
          },
          'subscription' => {
            'plan_code' => plan_code
          }
        })
      end

      # @deprecated Use {#generate_signature} instead.
      # @return [String]
      def sign_billing_info account_code
        generate_signature({
          'account' => {
            'account_code' => account_code
          }
        })
      end

      # @deprecated Use {#generate_signature} instead.
      # @return [String]
      def sign_transaction(amount_in_cents, currency = nil, account_code = nil)
        generate_signature({
          'account' => {
            'account_code' => account_code
          },
          'transaction' => {
            'amount_in_cents' => amount_in_cents,
            'currency' => currency || Recurly.default_currency
          }
        })
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

      def hash(protected_string)
        OpenSSL::HMAC.hexdigest('sha1', private_key, protected_string)
      end

      # convert data hash to a form encoded string
      def convert_to_query_string(data = {})
        data = process_data(data.dup)
        data[:timestamp] = Time.now.to_i

        address = Addressable::URI.new
        address.query_values = data
        address.query
      end

      # recursively process the query data (running to_s on values)
      def process_data(data = {})
        return data unless data.is_a?(Hash)
        data.each do |key, val|
          if val.is_a?(Hash)
            data[key] = process_data(val)
          elsif val.is_a?(String)
            data[key] = val.to_s
          elsif val.is_a?(Enumerable)
            values = Hash.new
            val.each_with_index{ |item, index| values[index] = process_data(item) }
            data[key] = values
          else
            data[key] = val.to_s
          end
        end
      end

      # absolute number of seconds between the timestamp and now
      def time_difference(timestamp)
        (timestamp.to_i - Time.now.to_i).abs
      end
    end
  end
end
