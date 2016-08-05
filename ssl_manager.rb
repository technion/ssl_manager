require 'sinatra/base'
require 'openssl'
require 'tempfile'
require 'zip'

class SSL_Manager < Sinatra::Base

  
  def create_csr(rsa_key, subject)
    csr = OpenSSL::X509::Request.new
    csr.subject = OpenSSL::X509::Name.new([
      ["C", "AU"],
      ["ST", "NSW"],
      ["O", "Organisation"],
      ["CN", subject]
    ])
    csr.public_key = rsa_key.public_key
    csr.sign rsa_key, OpenSSL::Digest::SHA256.new
    csr
  end

  get '/' do
    'Hello world'
  end

  get '/create' do
    halt 401, 'Missing subject' unless subject = params['subject']
    rsa_key = OpenSSL::PKey::RSA.new(2048)    
    csr = create_csr(rsa_key, subject)
    
    zipfile = Tempfile.new ['ssl', '.zip']

    Zip::OutputStream.open(zipfile) do |archive| 
      archive.put_next_entry("#{subject}.key")
      archive.write rsa_key.to_pem
      archive.put_next_entry("#{subject}.csr")
      archive.write csr.to_pem
    end
    send_file zipfile.path, filename: "#{subject}.zip"
    zipfile.unlink
    zipfile.close
  end
end
