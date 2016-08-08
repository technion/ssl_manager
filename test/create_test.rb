require './ssl_manager'
require 'minitest/autorun'
require 'rack/test'

# GLobal allows it to be used throughout tests.
config_file = File.read('ssl_manager_config.json-example')
$ssl_config = JSON.parse(config_file)
SSLManager.set :ssl_config, $ssl_config

class SSLManagerTest < Minitest::Test
  include Rack::Test::Methods

  def app
    SSLManager
  end

  def get_domain_from_csr(csr)
    subject = csr.subject.to_s
    /([^=]+)\z/.match(subject)[1]
  end

  def test_endpoint
    get '/test'
    assert_equal 404, last_response.status

    get '/create?subject=example.com' # Missing domainlist
    assert_equal 401, last_response.status
  end


  def test_create_cert
    get '/create?subject=example.com&domainlist=www.example.com,ftp.example.com'
    assert_equal 200, last_response.status

    zipfile = Tempfile.new ['ssl', '.zip']
    zipfile.write last_response.body
    zipfile.rewind

    key, csr_text = [nil, nil]

    # The contents of the .zip file are text files for key and csr
    Zip::File.open(zipfile.path) do |zip_file|
      zip_file.each do |entry|
        key = entry.get_input_stream.read if /key$/.match(entry.name)
        csr_text = entry.get_input_stream.read if /csr$/.match(entry.name)
      end
    end

    # Test the delivered CSR is valid and contained the correct domains
    assert csr_text
    assert csr = OpenSSL::X509::Request.new(csr_text)
    assert csr.verify(csr.public_key)
    assert_equal 'example.com', get_domain_from_csr(csr)

    # Test key decrypts
    assert key
    assert_raises OpenSSL::PKey::RSAError do
      OpenSSL::PKey::RSA.new(key, "wrong passphrase")
    end
    assert decrypted_key = 
      OpenSSL::PKey::RSA.new(key, $ssl_config['secret'])
    assert decrypted_key.private?

    # Cleanup
    zipfile.unlink
    zipfile.close
  end
end
