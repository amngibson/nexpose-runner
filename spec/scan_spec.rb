require 'nexpose-runner/scan'


describe 'nexpose-runner' do
  describe 'scan' do
    before(:each) do
      @expected_connection = 'http://test.connection'
      @expected_username = 'rapid7'
      @expected_password = 'password'
    end


      it 'should create a session with the nexpose server' do

        expect(Nexpose::Connection).to receive(:new)
                                        .with(@expected_connection, @expected_username, @expected_password)
                                        .and_return('<LoginRequest sync-id="arbitrary_integer" user-id="my-username" password="my-password"/>')

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password)
      end

      #it 'should throw an error if no connection url is passed' do

     # end

     # it 'should throw an error if no username is passed' do

     # end

     # it 'should throw an error if no password is passed' do

     # end

      #it 'should throw an error if no site name is passed' do

      #end

      #it 'should throw an error if no ip address is passed' do

      #end

      #it 'should use 3780 as default if port is empty string' do

      #end

      #it 'should use 3780 as default if port is nil' do

      #end

      #it 'should create a new site with the supplied site name' do

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


