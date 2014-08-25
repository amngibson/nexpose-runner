require 'nexpose/scan'

describe 'nexpose' do
  describe 'scan' do
    before(:each) do
      @expected_connection = 'http://spec.connection'
      @expected_port = '3781'
      @expected_username = 'rapid7'
      @expected_password = 'password'
      @expected_site_name = 'sitename'
      @expected_scan_template = 'full_audit'
      @expected_site_id = '33'
      @expected_scan_id = '12'
      @mock_device_ip_to_scan = '127.0.0.1'
    end


      it 'should create a session with the nexpose server' do

      end

      it 'should throw an error if no connection url is passed' do

      end

      it 'should throw an error if no username is passed' do

      end

      it 'should throw an error if no password is passed' do

      end

      it 'should throw an error if no site name is passed' do

      end

      it 'should throw an error if no ip address is passed' do

      end



      it 'should use 3780 as default if port is empty string' do

      end

      it 'should use 3780 as default if port is nil' do

      end

  end
end



