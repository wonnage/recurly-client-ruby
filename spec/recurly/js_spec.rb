require 'spec_helper'

describe Recurly.js do
  let(:js) { Recurly.js }

  describe "private_key" do
    it "must be assignable" do
      Recurly.js.private_key = 'a_private_key'
      Recurly.js.private_key.should == 'a_private_key'
    end

    it "must raise an exception when not set" do
      if Recurly.js.instance_variable_defined? :@private_key
        Recurly.js.send :remove_instance_variable, :@private_key
      end
      lambda { Recurly.js.private_key }.should raise_exception(ConfigurationError)
    end

    it "must raise an exception when set to nil" do
      Recurly.js.private_key = nil
      lambda { Recurly.js.private_key }.should raise_exception(ConfigurationError)
    end
  end

  describe "#generate_signature" do
    before(:each) do
      Recurly.js.private_key = '0123456789abcdef0123456789abcdef'
      Time.stub(:now).and_return 1329942896
    end

    it "should sign transaction request" do
      signature = Recurly.js.generate_signature({
        'account' => { 'account_code' => '123' },
        'transaction' => {
          'amount_in_cents' => 5000,
          'currency' => 'USD'
        }
      })

      signature.should == "5dcbd65498c62c552a6f78edfb117cada8cb4f00|account[account_code]=123&timestamp=1329942896&transaction[amount_in_cents]=5000&transaction[currency]=USD"
    end

    it "should sign subscription request" do
      signature = Recurly.js.generate_signature({
        'account' => { 'account_code' => '123' },
        'subscription' => {
          'plan_code' => 'gold'
        }
      })

      signature.should == "68d95a0bbc289e564bcb519511676d84d4a4cb96|account[account_code]=123&subscription[plan_code]=gold&timestamp=1329942896"
    end
  end
  
  describe "#validate_signature!" do
    before(:each) do
      Recurly.js.private_key = '0123456789abcdef0123456789abcdef'
      Time.stub(:now).and_return 1329942896
    end

    it "should validate a signature" do
      signature = 'c595b8093d7c1549fff7c418dcda80a310b35bc2|account[account_code]=112358132134&timestamp=1329942996'
      signature_data = Recurly.js.validate_signature! signature
      signature_data['account']['account_code'].should == '112358132134'
    end

    it "should raise an exception if the timestamp is old" do
      signature = 'f94a0c2b687c57be3b4cba59813c1aacba226cb5|account[account_code]=112358132134&timestamp=1329932896'
      lambda {
        signature_data = Recurly.js.validate_signature! signature
      }.should raise_exception(Recurly::JS::RequestTooOldError)
    end
  end

  describe "legacy signatures" do
    before(:each) do
      Recurly.js.private_key = '0123456789abcdef0123456789abcdef'
      Time.stub(:now).and_return 1329942896
    end

    it "should sign update billing info request" do
      signature = Recurly.js.sign_billing_info('123')
      signature.should == "1934b44c3fba8b6da31c16032f07ecaa24496267|account[account_code]=123&timestamp=1329942896"
    end

    it "should sign subscription request" do
      signature = Recurly.js.sign_subscription('gold', '123')
      signature.should == "68d95a0bbc289e564bcb519511676d84d4a4cb96|account[account_code]=123&subscription[plan_code]=gold&timestamp=1329942896"
    end

    it "should sign transaction request" do
      signature = Recurly.js.sign_transaction(5000, 'USD', '123')
      signature.should == "5dcbd65498c62c552a6f78edfb117cada8cb4f00|account[account_code]=123&timestamp=1329942896&transaction[amount_in_cents]=5000&transaction[currency]=USD"
    end
  end
end
