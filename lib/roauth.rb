require "base64"
require "openssl"
require "uri"

module ROAuth
  class UnsupportedSignatureMethod < Exception; end
  class MissingOAuthParams < Exception; end

  # Supported {signature methods}[http://oauth.net/core/1.0/#signing_process];
  SIGNATURE_METHODS = {"HMAC-SHA1" => OpenSSL::Digest::Digest.new("sha1")}
  OAUTH_PARAMS      = [:consumer_key, :token, :signature_method, :version, :nonce, :timestamp, :body_hash, :callback]

  # Return an {OAuth "Authorization" HTTP header}[http://oauth.net/core/1.0/#auth_header] from request data
  def header(oauth, uri, params = {}, http_method = :get)
    oauth = oauth.dup
    oauth[:signature_method] ||= "HMAC-SHA1"
    oauth[:version]          ||= "1.0" # Assumed version, according to the spec
    oauth[:nonce]            ||= Base64.encode64(OpenSSL::Random.random_bytes(32)).gsub(/\W/, '')
    oauth[:timestamp]        ||= Time.now.to_i
    oauth[:token]            ||= oauth.delete(:access_key)
    oauth[:token_secret]     ||= oauth.delete(:access_secret)

    sig_params = oauth_params(oauth)
    sig_params[:oauth_signature] = escape(
      signature(oauth, uri, sig_params.merge(params), http_method)
      )
    sorted_sig_params    = sig_params.sort_by{|k,v| [k.to_s, v.to_s] }
    authorization_params = sorted_sig_params.map {|key, value| [key, "\"#{value}\""].join("=") }.join(", ")

    %{OAuth } + authorization_params
  end

  def parse(header)
    header = header.dup
    header = header.gsub!(/^OAuth\s/, "")
    header = header.split(", ")
    header = header.inject({}) {|hash, item|
      key, value = item.split("=")
      key.gsub!(/^oauth_/, "")
      value.gsub!(/(^"|"$)/, "")
      hash[key.to_sym] = unescape(value)
      hash
    }
    header[:access_key] = header[:token]
    header
  end

  def verify(oauth, header, uri, params = {}, http_method = :get)
    header = header.is_a?(String) ? parse(header) : header.dup

    client_signature = header.delete(:signature)
    oauth[:consumer_key]     ||= header[:consumer_key]
    oauth[:token]            ||= header[:token]
    oauth[:token_secret]     ||= oauth.delete(:access_secret)
    oauth[:signature_method] ||= "HMAC-SHA1"
    oauth[:version]          ||= "1.0"

    sig_params = params.dup
    sig_params.merge!(oauth_params(header))

    client_signature == signature(oauth, uri, sig_params, http_method)
  end

  protected
    def oauth_params(oauth)
      oauth = oauth.to_a.select {|key, value|
        OAUTH_PARAMS.include?(key)
      }
      oauth.inject({}) {|hash, (key, value)|
        hash["oauth_#{key}"] = escape(value)
        hash
      }
    end

    def signature(oauth, uri, params, http_method = :get)
      uri = URI.parse(uri)
      uri.query = nil
      uri = uri.to_s

      sig_base = http_method.to_s.upcase + "&" + escape(uri) + "&" + escape(normalize(params))
      digest   = SIGNATURE_METHODS[oauth[:signature_method]]
      secret   = "#{escape(oauth[:consumer_secret])}&#{escape(oauth[:token_secret])}"

      Base64.encode64(OpenSSL::HMAC.digest(digest, secret, sig_base)).chomp.gsub(/\n/, "")
    end

    # Escape characters in a string according to the {OAuth spec}[http://oauth.net/core/1.0/]
    def escape(value)
      URI.escape(value.to_s, /[^a-zA-Z0-9\-\.\_\~]/) # Unreserved characters -- must not be encoded
    end

    def unescape(value)
      URI.unescape(value)
    end

    # Normalize a string of parameters based on the {OAuth spec}[http://oauth.net/core/1.0/#rfc.section.9.1.1]
    def normalize(params)
      # Stringify keys - so we can compare them
      params.keys.each {|key| params[key.to_s] = params.delete(key) }
      params.sort_by {|key, values| key.to_s }.map do |key, values|
        if values.is_a?(Array)
          # Multiple values were provided for a single key
          # in a hash
          values.sort_by(&:to_s).collect do |v|
            [escape(key), escape(v)] * "="
          end
        else
          [escape(key), escape(values)] * "="
        end
      end * "&"
    end
  extend self
end