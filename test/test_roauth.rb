require 'helper'

class TestRoauth < Test::Unit::TestCase
  should "correctly sign params" do
    url = "https://twitter.com/direct_messages.json"

    oauth = {
      :consumer_key    => "consumer_key",
      :consumer_secret => "consumer_secret",
      :access_key      => "access_key",
      :access_secret   => "access_secret",
      :nonce           => "foo",
      :timestamp       => 1286967499
    }
    
    params = {
      :count    => "11",
      :since_id => "5000"
    }
    
    oauth_header = ROAuth.header(oauth, url, params)
    signature    = ROAuth.parse(oauth_header)[:signature]
    puts oauth_header
        
    assert_equal "9/g1ge6nLYVkBsTEqgxH0Xlv2O4=", signature
  end
  
  should "verify correctly signed params" do 
    url = "https://twitter.com/direct_messages.json"
    
    oauth = {
      :consumer_key    => "consumer_key",
      :consumer_secret => "consumer_secret",
      :access_key      => "access_key",
      :access_secret   => "access_secret",
      :nonce           => "foo",
      :timestamp       => 1286967499
    }
    
    params = {
      :count    => "11",
      :since_id => "5000"
    }
    
    header = %{OAuth oauth_consumer_key="consumer_key", oauth_nonce="foo", oauth_signature="9%2Fg1ge6nLYVkBsTEqgxH0Xlv2O4%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1286967499", oauth_token="access_key", oauth_version="1.0"}
    assert ROAuth.verify(oauth, header, url, params), "verify failed"
  end
end