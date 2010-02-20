Based on SOAuth: http://github.com/tofumatt/SOAuth

A *simple* OAuth library that supports OAuth header signing, and header verifying.
  
    gem install roauth

Example Client:

    uri = "https://twitter.com/direct_messages.json"

    oauth = {
    :consumer_key    => "consumer_key",
    :consumer_secret => "consumer_secret",
    :access_key      => "access_key",
    :access_secret   => "access_secret"
    }

    params = {
    :count    => "11",
    :since_id => "5000"
    }
    oauth_header = ROAuth.header(oauth, uri, params)

    http_uri = URI.parse(uri)
    request  = Net::HTTP.new(http_uri.host, http_uri.port)
    request.get(uri.request_uri, {'Authorization', oauth_header})

Example Server:

    oauth_header = ROAuth.parse(request.header['Authorization'])

    # Implementation specific
    consumer     = Consumer.find_by_key(oauth_header[:consumer_key])
    access_token = AccessToken.find_by_token(oauth_header[:access_key])
    oauth = {
      :consumer_secret => consumer.secret,
      :access_secret   => access_token.secret
    }

    ROAuth.verify(oauth, oauth_header, request.request_uri, params) #=> true/false