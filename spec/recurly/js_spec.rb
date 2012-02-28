require 'spec_helper'

describe Recurly.js do
  let(:js) { Recurly.js }

  describe "private_key" do
    it "must be assignable" do
      js.private_key = 'a_private_key'
      js.private_key.must_equal 'a_private_key'
    end

    it "must raise an exception when not set" do
      if js.instance_variable_defined? :@private_key
        js.send :remove_instance_variable, :@private_key
      end
      proc { Recurly.js.private_key }.must_raise ConfigurationError
    end

    it "must raise an exception when set to nil" do
      Recurly.js.private_key = nil
      proc { Recurly.js.private_key }.must_raise ConfigurationError
    end
  end

  describe ".sign" do
    let(:sign) { js.method :sign }
    let(:private_key) { '0123456789abcdef0123456789abcdef' }
    let(:timestamp) { 1329942896 }

    class MockTime
      class << self
        attr_accessor :now
      end
    end

    before do
      js.private_key = '0123456789abcdef0123456789abcdef'
      @time = Time
      Object.const_set :Time, MockTime
      Time.now = @time.at timestamp
    end

    after do
      Object.const_set :Time, @time
    end

    it "must sign transaction request" do
      Recurly.js.sign(
        'account' => { 'account_code' => '123' },
        'transaction' => {
          'amount_in_cents' => 5000,
          'currency' => 'USD'
        }
      ).must_equal <<EOS.chomp
f9d7cc07a27a6dbd09098ef0430899ece3457237|\
account%5Baccount_code%5D=123&\
timestamp=1329942896&\
transaction%5Bamount_in_cents%5D=5000&\
transaction%5Bcurrency%5D=USD
EOS
    end

    it "must sign subscription request" do
      Recurly.js.sign(
        'account' => { 'account_code' => '123' },
        'subscription' => {
          'plan_code' => 'gold'
        }
      ).must_equal <<EOS.chomp
4c13a03b0e1f388ec1bd59233a289748ac4f60cc|\
account%5Baccount_code%5D=123&\
subscription%5Bplan_code%5D=gold&\
timestamp=1329942896
EOS
    end
  
    describe ".verify!" do
      let(:verify) { js.method :verify! }

      it "must verify a signature" do
        params = Recurly.js.verify! <<EOS.chomp
c595b8093d7c1549fff7c418dcda80a310b35bc2|\
account[account_code]=112358132134&\
timestamp=1329942996
EOS
        params['account']['account_code'].must_equal '112358132134'
      end

      it "must raise an exception if the timestamp is old" do
        proc { Recurly.js.verify! <<EOS.chomp }.must_raise js::RequestTooOld
f94a0c2b687c57be3b4cba59813c1aacba226cb5|\
account[account_code]=112358132134&\
timestamp=1329932896
EOS
      end
    end

    describe "legacy signatures" do
      it "must sign update billing info request" do
        Recurly.js.sign_billing_info('123').must_equal <<EOS.chomp
ff9802a95d529b97d03780935a739f33592271e8|\
account%5Baccount_code%5D=123&\
timestamp=1329942896
EOS
      end

      it "must sign subscription request" do
        Recurly.js.sign_subscription('gold', '123').must_equal <<EOS.chomp
4c13a03b0e1f388ec1bd59233a289748ac4f60cc|\
account%5Baccount_code%5D=123&\
subscription%5Bplan_code%5D=gold&\
timestamp=1329942896
EOS
      end

      it "must sign transaction request" do
        Recurly.js.sign_transaction(5000, 'USD', '123').must_equal <<EOS.chomp
f9d7cc07a27a6dbd09098ef0430899ece3457237|\
account%5Baccount_code%5D=123&\
timestamp=1329942896&\
transaction%5Bamount_in_cents%5D=5000&\
transaction%5Bcurrency%5D=USD
EOS
      end
    end
  end
end
