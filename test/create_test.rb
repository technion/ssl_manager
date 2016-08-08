require './ssl_manager'
require 'minitest/autorun'
require 'rack/test'

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
    assert key
    assert csr_text
    assert csr = OpenSSL::X509::Request.new(csr_text)
    assert csr.verify(csr.public_key)
    assert_equal 'example.com', get_domain_from_csr(csr)

    zipfile.unlink
    zipfile.close
  end
end
