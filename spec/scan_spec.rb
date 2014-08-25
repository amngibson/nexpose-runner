require 'nexpose-runner/scan'


describe 'nexpose-runner' do
  describe 'scan' do
    before(:each) do
      @expected_connection = 'http://test.connection'
      @expected_username = 'rapid7'
      @expected_password = 'password'
    end


      it 'should create a session with the nexpose-runner server' do

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

  end
end


