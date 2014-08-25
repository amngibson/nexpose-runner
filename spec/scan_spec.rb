require 'nexpose-runner/scan'


describe 'nexpose-runner' do
  describe 'scan' do
    before(:each) do
      @expected_connection = 'http://test.connection'
      @expected_username = 'rapid7'
      @expected_password = 'password'
      @expected_port = '3781'
      @expected_site_name = 'my_cool_software_build-28'
      @expected_ip = '10.5.0.15'
      @mock_nexpose_client = get_mock_nexpose_client
      @mock_session_id = 'ED3B7315775C3950DD53119D8E317B9D8886752C'
    end


      it 'should create a session with the nexpose server' do

        expect(Nexpose::Connection).to receive(:new)
                                    .with(@expected_connection, @expected_username, @expected_password, @expected_port)
                                    .and_return(@mock_nexpose_client)
        expect(@mock_nexpose_client).to receive(:login)
                                    .and_return(true)

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip)

      end

      it 'should throw an error if no connection url is passed' do
        expect { NexposeRunner::Scan.start('', @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me the URL/IP address to your Nexpose Server')
        expect { NexposeRunner::Scan.start(nil, @expected_port, @expected_username, @expected_password, @expected_site_name, @expected_ip) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me the URL/IP address to your Nexpose Server')
      end

      it 'should throw an error if no username is passed' do
        expect { NexposeRunner::Scan.start(@expected_connection, '', @expected_password, @expected_port, @expected_site_name, @expected_ip) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a username to login to Nexpose with')
        expect { NexposeRunner::Scan.start(@expected_connection, nil, @expected_password, @expected_port, @expected_site_name, @expected_ip) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a username to login to Nexpose with')
      end

      it 'should throw an error if no password is passed' do
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, '', @expected_port, @expected_site_name, @expected_ip) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a password to login to Nexpose with')
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, nil, @expected_port, @expected_site_name, @expected_ip) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a password to login to Nexpose with')
      end

      it 'should use 3780 as default if port is empty string' do

        expect(Nexpose::Connection).to receive(:new)
                                  .with(@expected_connection, @expected_username, @expected_password, '3780')
                                  .and_return(@mock_nexpose_client)

        expect(@mock_nexpose_client).to receive(:login)
                                        .and_return(true)

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, '', @expected_site_name, @expected_ip)
      end

      it 'should throw an error if no site name is passed' do
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, '', @expected_ip) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a Nexpose Site Name')
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, nil, @expected_ip) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a Nexpose Site Name')
      end

      it 'should throw an error if no ip address is passed' do
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, '') }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me an IP Address to scan')
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, nil) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me an IP Address to scan')
      end


      #it 'should create a new Nexpose site with the supplied site name' do

      #end

      #it 'should add the supplied ip address to the newly created site' do

      #end

      #it 'should initiate a new scan against the newly create site with the supplied scan template' do

      #end

      #it 'should check and output the status of the scan every 3 seconds until its complete' do

      #end

      #it 'should download an adhoc report in CSV format with all the detected vulnerabilities ' do

      #end

      #it 'should download an adhoc report in CSV format with all the detected installed software ' do

      #end

      #it 'should download an adhoc report in CSV format with all the detected policy checks ' do

      #end

  end
end

def get_mock_nexpose_client
  mock_nexpose_client = double(Nexpose::Connection)

  allow(mock_nexpose_client).to receive(:call).with(any_args).and_return({})

  allow(Nexpose::Connection).to receive(:new)
                             .and_return(mock_nexpose_client)

  mock_nexpose_client
end
