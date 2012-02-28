module Recurly
  module JS
    module DeprecatedMethods
      # @deprecated Use {.sign!} instead.
      # @return [String]
      def sign_subscription plan_code, account_code = nil
        deprecated!
        sign(
          'account'      => { 'account_code' => account_code },
          'subscription' => { 'plan_code'    => plan_code }
        )
      end

      # @deprecated Use {.sign!} instead.
      # @return [String]
      def sign_billing_info account_code
        deprecated!
        sign('account' => { 'account_code' => account_code })
      end

      # @deprecated Use {.sign!} instead.
      # @return [String]
      def sign_transaction(amount_in_cents, currency = nil, account_code = nil)
        deprecated!
        sign(
          'account'     => { 'account_code' => account_code },
          'transaction' => {
            'amount_in_cents' => amount_in_cents,
            'currency'        => currency || Recurly.default_currency
          }
        )
      end

      # @deprecated Use {.verify!} instead.
      # @return [true]
      # @raise [RequestForgery] If verification fails.
      def verify_subscription! params
        deprecated!
        verify_signature! params[:signature]
      end

      # @deprecated Use {.verify!} instead.
      # @return [true]
      # @raise [RequestForgery] If verification fails.
      def verify_billing_info! params
        deprecated!
        verify_signature! params[:signature]
      end

      # @deprecated Use {.verify!} instead.
      # @return [true]
      # @raise [RequestForgery] If verification fails.
      def verify_transaction! params
        deprecated!
        verify_signature! params[:signature]
      end

      private

      def deprecated!
        Recurly.log :warn, <<EOE.chomp
Recurly.js.#{caller[0][/`[^']+'$/][1..-2]} is deprecated! \
(called from #{caller[1]})
EOE
      end
    end

    extend DeprecatedMethods
  end
end
