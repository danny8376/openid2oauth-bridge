#!/usr/bin/env ruby

require 'securerandom'
require 'json'
require 'sinatra'
require 'thin'
require 'openid'
require 'openid/extensions/sreg'
require 'openid/extensions/pape'
require 'openid/store/memory'
require 'rack/oauth2'

include OpenID::Server

require './CONFIG'

# ==== Sinatra Config ====
configure do
  mime_type :xrds, 'application/xrds+xml'
  enable :sessions
  set :session_secret, ENV.fetch('SESSION_SECRET') { SERVER_CONF[:session_secret] || SecureRandom.hex(64) }
  set :server, 'thin'
  set :bind, SERVER_CONF[:bind]
  set :port, SERVER_CONF[:port]
end

# ==== Routes ====
get "#{SERVER_CONF[:prefix]}", provides: :html do
  openid
end

get "#{SERVER_CONF[:prefix]}", provides: :xrds do
  idp_xrds
end

post "#{SERVER_CONF[:prefix]}" do
  openid
end

get "#{SERVER_CONF[:prefix]}:username", provides: :html do |username|
  user_page username
end

get "#{SERVER_CONF[:prefix]}:username", provides: :xrds do |username|
  user_xrds username
end

# ==== Methods ====
def user_url(username = session[:username])
  "#{base_url}#{SERVER_CONF[:prefix]}#{username}"
end

def base_url
  SERVER_CONF[:base_url] || "#{request.scheme}://#{request.host}#{":#{request.port}" unless request.forwarded?}"
end

def user_page(username)
  xrds_url = "#{user_url(username)}"
  server_url = "#{SERVER_CONF[:prefix]}"

  headers({
    'X-XRDS-Location' => xrds_url
  })

<<EOS
<html><head>
<meta http-equiv="X-XRDS-Location" content="#{xrds_url}" />
<link rel="openid.server" href="#{server_url}" />
</head><body><p>OpenID identity page for #{username}</p>
</body></html>
EOS

end

def user_xrds(username)
  render_xrds [
    OpenID::OPENID_2_0_TYPE,
    OpenID::OPENID_1_0_TYPE,
    OpenID::SREG_URI,
  ]
end

def idp_page
  xrds_url = "#{SERVER_CONF[:prefix]}"
  server_url = "#{SERVER_CONF[:prefix]}"

  headers({
    'X-XRDS-Location' => xrds_url
  })

<<EOS
<html><head>
<meta http-equiv="X-XRDS-Location" content="#{xrds_url}" />
<link rel="openid.server" href="#{server_url}" />
</head><body><p>OpenID identity server</p>
</body></html>
EOS

end

def idp_xrds
  render_xrds [
    OpenID::OPENID_2_0_TYPE,
  ]
end

def render_xrds(types)
  content_type :xrds

  server_url = "#{base_url}"

<<EOS
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://$xrds"
    xmlns="xri://$xrd*($v*2.0)">
  <XRD>
    <Service priority="0">
#{types.map { |uri| "      <Type>#{uri}</Type>" }.join("\n")}
      <URI>#{server_url}</URI>
    </Service>
  </XRD>
</xrds:XRDS>
EOS

end

def store
  # TODO: storage config
  OpenID::Store::Memory.new
end

def server
  if $server.nil?
    server_url = "#{base_url}"
    $server = Server.new(store, server_url)
  end
  $server
end

def oauth
  if $oauth.nil?
    redirect_uri = "#{base_url}"
    $oauth = Rack::OAuth2::Client.new(OAUTH_CONF.merge({
      identifier: OAUTH_CONF[:client_id],
      secret: OAUTH_CONF[:client_secret],
      redirect_uri: redirect_uri
    }))
  end
  $oauth
end

def approved(trust_root)
  return false if session[:approvals].nil?
  return session[:approvals].member?(trust_root)
end

def is_authorized(identity_url, trust_root)
  return (session[:username] and (identity_url == user_url) and approved(trust_root))
end

def openid
  return oauth_callback if params['code']

  oidreq = server.decode_request(params)
  return idp_page unless oidreq

  oidresp = nil
  if oidreq.kind_of?(CheckIDRequest)
    identity = oidreq.identity
    if oidreq.id_select
      if oidreq.immediate
        oidresp = oidreq.answer(false)
      elsif session[:username].nil? # The user hasn't logged in.
        session[:last_oidreq] = oidreq
        return oauth_redirect
      else
        identity = user_url
      end
    end
    if oidresp
      nil
    elsif is_authorized(identity, oidreq.trust_root)
      oidresp = oidreq.answer(true, nil, identity)

      add_sreg(oidreq, oidresp) # add the sreg response if requested
      add_pape(oidreq, oidresp) # ditto pape
    elsif oidreq.immediate
      server_url = "#{SERVER_CONF[:prefix]}"
      oidresp = oidreq.answer(false, server_url)
    else
      session[:last_oidreq] = oidreq
      return oauth_redirect
    end
  else
    oidresp = server.handle_request(oidreq)
  end

  render_response(oidresp)
rescue ProtocolError => e
  [500, e.to_s]
end

def oauth_redirect
  session[:state] = SecureRandom.hex(16)
  redirect oauth.authorization_uri(
    scope: OAUTH_CONF[:scope],
    state: session[:state]
  )
end

def add_sreg(oidreq, oidresp)
  # check for Simple Registration arguments and respond
  sregreq = OpenID::SReg::Request.from_openid_request(oidreq)

  return if sregreq.nil?
  # In a real application, this data would be user-specific,
  # and the user should be asked for permission to release
  # it.
  sreg_data = {
    'nickname' => session[:username],
    'fullname' => 'Mayor McCheese',
    'email' => 'mayor@example.com'
  }

  sregresp = OpenID::SReg::Response.extract_response(sregreq, sreg_data)
  oidresp.add_extension(sregresp)
end

def add_pape(oidreq, oidresp)
  papereq = OpenID::PAPE::Request.from_openid_request(oidreq)
  return if papereq.nil?
  paperesp = OpenID::PAPE::Response.new
  paperesp.nist_auth_level = 0 # we don't even do auth at all!
  oidresp.add_extension(paperesp)
end

def render_response(oidresp)
  if oidresp.needs_signing
    signed_response = server.signatory.sign(oidresp)
  end
  web_response = server.encode_response(oidresp)

  case web_response.code
  when HTTP_OK
    web_response.body
  when HTTP_REDIRECT
    redirect web_response.headers['location']
  else
    [400, web_response.body]
  end
end

def oauth_callback
  # verify state
  return redirect oidreq.cancel_url unless session[:state] == params['state']

  oauth.authorization_code = params['code']
  token = oauth.access_token! # TODO: config for :body mode

  oidreq = session[:last_oidreq]
  session[:last_oidreq] = nil

  userinfo = JSON.parse(token.get(USERNAME_MAPPING[:userinfo_endpoint]).body) rescue {}
  username = userinfo[USERNAME_MAPPING[:username_attribute]] rescue nil

  identity = oidreq.identity
  if oidreq.id_select
    if username and username != ""
      session[:username] = username
      session[:approvals] = []
      identity = user_url
    else
      return redirect oidreq.cancel_url # oauth failed
    end
  end

  if session[:approvals]
    session[:approvals] << oidreq.trust_root
  else
    session[:approvals] = [oidreq.trust_root]
  end
  oidresp = oidreq.answer(true, nil, identity)
  add_sreg(oidreq, oidresp)
  add_pape(oidreq, oidresp)
  return render_response(oidresp)
end

