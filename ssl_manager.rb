require 'sinatra/base'
require 'openssl'

class SSL_Manager < Sinatra::Base

  get '/' do
    'Hello world'
  end

  get '/create' do
    rsa_key = OpenSSL::PKey::RSA.new(2048)    
    halt 401, 'Missing subject' unless subject = params['subject']
    
    csr = OpenSSL::X509::Request.new
    csr.subject = OpenSSL::X509::Name.new([
      ["C", "AU"],
      ["ST", "NSW"],
      ["O", "Organisation"],
      ["CN", subject]
    ])
    csr.public_key = rsa_key.public_key
    csr.sign rsa_key, OpenSSL::Digest::SHA256.new
    rsa_key.to_pem + rsa_key.public_key.to_pem + csr.to_pem
  end
end
