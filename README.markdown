Based on SOAuth: http://github.com/tofumatt/SOAuth
  
  gem install roauth

Example Client:

	uri = 'https://twitter.com/direct_messages.json'
	oauth = {
    :consumer_key    => "consumer_key",
    :consumer_secret => "consumer_secret",
    :token           => "access_key",
    :token_secret    => "access_secret"
	}
	params = {
		'count'    => "11",
		'since_id' => "5000"
	}
	oauth_header = ROAuth.header(oauth, uri, params)

	http_uri = URI.parse(uri)
	request  = Net::HTTP.new(http_uri.host, http_uri.port)
	request.get(uri.request_uri, {'Authorization', oauth_header})

Example Server:
  
	request_oauth = ROAuth.parse(request.header['Authorization'])
	
	# Implementation specific
	consumer     = Consumer.find_by_key(request_oauth['consumer_key'])
	access_token = AccessToken.find_by_token(request_oauth['token'])
	oauth = {
	  :consumer_secret => consumer.secret,
	  :token_secret    => access_token.secret
	}
	
	OAuth.verify(oauth, request.request_uri, request_oauth, params) #=> true/false