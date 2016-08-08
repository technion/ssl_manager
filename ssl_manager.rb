require 'sinatra/base'
require 'openssl'
require 'tempfile'
require 'zip'

class SSL_Manager < Sinatra::Base

  def subject_alt_name(domains)
    domains = domains.split(/,/)
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.create_extension("subjectAltName", domains.map { |d| "DNS: #{d}" }.join(','))

  end
  
  def create_csr(rsa_key, subject, domainlist)
    csr = OpenSSL::X509::Request.new
    csr.subject = OpenSSL::X509::Name.new([
      ["C", "AU"],
      ["ST", "NSW"],
      ["O", "Organisation"],
      ["CN", subject]
    ])
    csr.public_key = rsa_key.public_key

    extensions = OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(
      [subject_alt_name(domainlist)])])
    csr.add_attribute(OpenSSL::X509::Attribute.new('extReq', extensions))
    csr.add_attribute(OpenSSL::X509::Attribute.new('msExtReq', extensions))

    csr.sign rsa_key, OpenSSL::Digest::SHA256.new
    csr
  end

  get '/' do
    'Hello world'
  end

  get '/create' do
    halt 401, 'Missing subject' unless subject = params['subject']
    halt 401, 'Missing domainlist' unless domainlist = params['domainlist']
    rsa_key = OpenSSL::PKey::RSA.new(2048)    
    csr = create_csr(rsa_key, subject, domainlist)
    
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
