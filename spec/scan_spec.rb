require 'nexpose-runner/scan'


describe 'nexpose-runner' do
  before(:each) do
    allow(NexposeRunner::Scan).to receive(:sleep)
  end

  describe 'scan' do
    before(:each) do
      @expected_connection = 'http://test.connection'
      @expected_username = 'rapid7'
      @expected_password = 'password'
      @expected_port = '3781'
      @expected_site_name = 'my_cool_software_build-28'
      @expected_ip = '10.5.0.15'
      @expected_scan_template = 'full-audit-widget-corp'
      @expected_vulnerability_query = 'SELECT DISTINCT
                                  ip_address,
                                  title,
                                  date_published,
                                  severity,
                                  summary,
                                  fix
                                FROM fact_asset_scan_vulnerability_finding
                                JOIN dim_asset USING (asset_id)
                                JOIN dim_vulnerability USING (vulnerability_id)
                                JOIN dim_vulnerability_solution USING (vulnerability_id)
                                JOIN dim_solution_highest_supercedence USING (solution_id)
                                JOIN dim_solution ds ON superceding_solution_id = ds.solution_id'
      @mock_scan_id = '12'
      @mock_site_id = '1'
      @mock_nexpose_client = get_mock_nexpose_client
      @mock_nexpose_site = get_mock_nexpose_site
      @mock_report = get_mock_report
    end


      it 'should create a session with the nexpose server' do

        expect(Nexpose::Connection).to receive(:new)
                                    .with(@expected_connection, @expected_username, @expected_password, @expected_port)
                                    .and_return(@mock_nexpose_client)

        expect(@mock_nexpose_client).to receive(:login)
                                    .and_return(true)

        expect(Nexpose::Site).to receive(:new)
                                 .with(@expected_site_name, @expected_scan_template)
                                 .and_return(@mock_nexpose_site)

        expect(@mock_nexpose_site).to receive(:add_ip)
                                      .with(@expected_ip)

        expect(@mock_nexpose_site).to receive(:save)
                                      .with(@mock_nexpose_client)
                                      .and_return('id' => @mock_site_id)

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return({'id' => @mock_scan_id})

        expect(@mock_nexpose_client).to receive(:scan_status)
                                        .with(@mock_scan_id)

        expect(Nexpose::AdhocReportConfig).to receive(:new)
                                              .with(nil, 'sql')
                                              .and_return(@mock_report)

        expect(@mock_report).to receive(:add_filter)
                                .with('version', '1.3.0')

        expect(@mock_report).to receive(:add_filter)
                                .with('query', @expected_vulnerability_query)

        expect(@mock_report).to receive(:add_filter)
                                .with('site', @mock_site_id)


        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)

      end

      it 'should throw an error if no connection url is passed' do
        expect { NexposeRunner::Scan.start('', @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me the URL/IP address to your Nexpose Server')
        expect { NexposeRunner::Scan.start(nil, @expected_port, @expected_username, @expected_password, @expected_site_name, @expected_ip, @expected_scan_template) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me the URL/IP address to your Nexpose Server')
      end

      it 'should throw an error if no username is passed' do
        expect { NexposeRunner::Scan.start(@expected_connection, '', @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a username to login to Nexpose with')
        expect { NexposeRunner::Scan.start(@expected_connection, nil, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a username to login to Nexpose with')
      end

      it 'should throw an error if no password is passed' do
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, '', @expected_port, @expected_site_name, @expected_ip, @expected_scan_template) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a password to login to Nexpose with')
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, nil, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a password to login to Nexpose with')
      end

      it 'should use 3780 as default if port is empty string' do

        expect(Nexpose::Connection).to receive(:new)
                                  .with(@expected_connection, @expected_username, @expected_password, '3780')
                                  .and_return(@mock_nexpose_client)

        expect(@mock_nexpose_client).to receive(:login)
                                        .and_return(true)

        expect(Nexpose::Site).to receive(:new)
                                 .with(@expected_site_name, @expected_scan_template)
                                 .and_return(@mock_nexpose_site)

        expect(@mock_nexpose_site).to receive(:add_ip)
                                      .with(@expected_ip)

        expect(@mock_nexpose_site).to receive(:save)
                                      .with(@mock_nexpose_client)
                                      .and_return('id' => @mock_site_id)

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return({'id' => @mock_scan_id})

        expect(@mock_nexpose_client).to receive(:scan_status)
                                        .with(@mock_scan_id)

        expect(Nexpose::AdhocReportConfig).to receive(:new)
                                              .with(nil, 'sql')
                                              .and_return(@mock_report)

        expect(@mock_report).to receive(:add_filter)
                                .with('version', '1.3.0')

        expect(@mock_report).to receive(:add_filter)
                                .with('query', @expected_vulnerability_query)

        expect(@mock_report).to receive(:add_filter)
                                .with('site', @mock_site_id)

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, '', @expected_site_name, @expected_ip, @expected_scan_template)
      end

      it 'should throw an error if no site name is passed' do
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, '', @expected_ip, @expected_scan_template) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a Nexpose Site Name')
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, nil, @expected_ip, @expected_scan_template) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a Nexpose Site Name')
      end

      it 'should throw an error if no ip address is passed' do
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, '', @expected_scan_template) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me an IP Address to scan')
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, nil, @expected_scan_template) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me an IP Address to scan')
      end

      it 'should throw an error if no scan template is passed' do
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, '') }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a Scan Template to use')
        expect { NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, nil) }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a Scan Template to use')
      end

      it 'should create a new Nexpose site with the supplied site name and scan template' do

        expect(@mock_nexpose_client).to receive(:login)
                                        .and_return(true)

        expect(Nexpose::Site).to receive(:new)
                                       .with(@expected_site_name, @expected_scan_template)
                                       .and_return(@mock_nexpose_site)

        expect(@mock_nexpose_site).to receive(:add_ip)
                                      .with(@expected_ip)

        expect(@mock_nexpose_site).to receive(:save)
                                      .with(@mock_nexpose_client)
                                      .and_return('id' => @mock_site_id)

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return({'id' => @mock_scan_id})

        expect(@mock_nexpose_client).to receive(:scan_status)
                                        .with(@mock_scan_id)

        expect(Nexpose::AdhocReportConfig).to receive(:new)
                                              .with(nil, 'sql')
                                              .and_return(@mock_report)

        expect(@mock_report).to receive(:add_filter)
                                .with('version', '1.3.0')

        expect(@mock_report).to receive(:add_filter)
                                .with('query', @expected_vulnerability_query)

        expect(@mock_report).to receive(:add_filter)
                                .with('site', @mock_site_id)

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
      end

      it 'should add the supplied ip address to the newly created site' do
        expect(@mock_nexpose_client).to receive(:login)
                                        .and_return(true)

        expect(Nexpose::Site).to receive(:new)
                                 .with(@expected_site_name, @expected_scan_template)
                                 .and_return(@mock_nexpose_site)

        expect(@mock_nexpose_site).to receive(:add_ip)
                                .with(@expected_ip)

        expect(@mock_nexpose_site).to receive(:save)
                                      .with(@mock_nexpose_client)
                                      .and_return('id' => @mock_site_id)

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return({'id' => @mock_scan_id})

        expect(@mock_nexpose_client).to receive(:scan_status)
                                        .with(@mock_scan_id)

        expect(Nexpose::AdhocReportConfig).to receive(:new)
                                              .with(nil, 'sql')
                                              .and_return(@mock_report)

        expect(@mock_report).to receive(:add_filter)
                                .with('version', '1.3.0')

        expect(@mock_report).to receive(:add_filter)
                                .with('query', @expected_vulnerability_query)

        expect(@mock_report).to receive(:add_filter)
                                .with('site', @mock_site_id)

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
      end

      it 'should save the new site configuration' do
        expect(@mock_nexpose_client).to receive(:login)
                                        .and_return(true)

        expect(Nexpose::Site).to receive(:new)
                                 .with(@expected_site_name, @expected_scan_template)
                                 .and_return(@mock_nexpose_site)

        expect(@mock_nexpose_site).to receive(:add_ip)
                                      .with(@expected_ip)

        expect(@mock_nexpose_site).to receive(:save)
                                      .with(@mock_nexpose_client)
                                      .and_return('id' => @mock_site_id)

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return({'id' => @mock_scan_id})

        expect(@mock_nexpose_client).to receive(:scan_status)
                                        .with(@mock_scan_id)

        expect(Nexpose::AdhocReportConfig).to receive(:new)
                                              .with(nil, 'sql')
                                              .and_return(@mock_report)

        expect(@mock_report).to receive(:add_filter)
                                .with('version', '1.3.0')

        expect(@mock_report).to receive(:add_filter)
                                .with('query', @expected_vulnerability_query)

        expect(@mock_report).to receive(:add_filter)
                                .with('site', @mock_site_id)

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
      end

      it 'should initiate a scan' do
        expect(@mock_nexpose_client).to receive(:login)
                                        .and_return(true)

        expect(Nexpose::Site).to receive(:new)
                                 .with(@expected_site_name, @expected_scan_template)
                                 .and_return(@mock_nexpose_site)

        expect(@mock_nexpose_site).to receive(:add_ip)
                                      .with(@expected_ip)

        expect(@mock_nexpose_site).to receive(:save)
                                      .with(@mock_nexpose_client)
                                      .and_return('id' => @mock_site_id)

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return({'id' => @mock_scan_id})

        expect(@mock_nexpose_client).to receive(:scan_status)
                                        .with(@mock_scan_id)

        expect(Nexpose::AdhocReportConfig).to receive(:new)
                                              .with(nil, 'sql')
                                              .and_return(@mock_report)

        expect(@mock_report).to receive(:add_filter)
                                .with('version', '1.3.0')

        expect(@mock_report).to receive(:add_filter)
                                .with('query', @expected_vulnerability_query)

        expect(@mock_report).to receive(:add_filter)
                                .with('site', @mock_site_id)

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
      end

      describe 'wait for the Nexpose Scan to complete' do
        before(:each) do
          expect(@mock_nexpose_client).to receive(:login)
                                          .and_return(true)

          expect(Nexpose::Site).to receive(:new)
                                   .with(@expected_site_name, @expected_scan_template)
                                   .and_return(@mock_nexpose_site)

          expect(@mock_nexpose_site).to receive(:add_ip)
                                        .with(@expected_ip)

          expect(@mock_nexpose_site).to receive(:save)
                                        .with(@mock_nexpose_client)
                                        .and_return('id' => @mock_site_id)

          expect(@mock_nexpose_site).to receive(:scan)
                                        .with(@mock_nexpose_client)
                                        .and_return({'id' => @mock_scan_id})

          expect(Nexpose::AdhocReportConfig).to receive(:new)
                                                .with(nil, 'sql')
                                                .and_return(@mock_report)

          expect(@mock_report).to receive(:add_filter)
                                  .with('version', '1.3.0')

          expect(@mock_report).to receive(:add_filter)
                                  .with('query', @expected_vulnerability_query)

          expect(@mock_report).to receive(:add_filter)
                                  .with('site', @mock_site_id)

        end
  
        it 'should call to check the status of the scan' do
          expect(@mock_nexpose_client).to receive(:scan_status).with(@mock_scan_id)
  
          NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
        end
  
        it 'should call to check the status until it is not running' do
          expect(@mock_nexpose_client).to receive(:scan_status)
                                      .with(@mock_scan_id)
                                      .and_return(Nexpose::Scan::Status::RUNNING)
                                      .exactly(3).times
                                      .ordered
  
          expect(@mock_nexpose_client).to receive(:scan_status)
                                      .with(@mock_scan_id)
                                      .and_return(Nexpose::Scan::Status::FINISHED)
                                      .once
                                      .ordered
  
          NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
        end
  
        it 'should sleep for 3 seconds if the status is still running' do
          expect(@mock_nexpose_client).to receive(:scan_status)
                                      .with(@mock_scan_id)
                                      .and_return(Nexpose::Scan::Status::RUNNING)
                                      .exactly(3).times
                                      .ordered
  
          expect(@mock_nexpose_client).to receive(:scan_status)
                                      .with(@mock_scan_id)
                                      .and_return(Nexpose::Scan::Status::FINISHED)
                                      .once
                                      .ordered

          expect(NexposeRunner::Scan).to receive(:sleep).with(3).exactly(4).times
  
          NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
        end
      end



      describe 'it should create reports' do
        before(:each) do
          expect(@mock_nexpose_client).to receive(:login)
                                          .and_return(true)

          expect(Nexpose::Site).to receive(:new)
                                   .with(@expected_site_name, @expected_scan_template)
                                   .and_return(@mock_nexpose_site)

          expect(@mock_nexpose_site).to receive(:add_ip)
                                        .with(@expected_ip)

          expect(@mock_nexpose_site).to receive(:save)
                                        .with(@mock_nexpose_client)
                                        .and_return('id' => @mock_site_id)

          expect(@mock_nexpose_site).to receive(:scan)
                                        .with(@mock_nexpose_client)
                                        .and_return({'id' => @mock_scan_id})

          expect(@mock_nexpose_client).to receive(:scan_status)
                                          .with(@mock_scan_id)

        end

        it 'should download an adhoc report in CSV format with all the detected vulnerabilities ' do

          expect(Nexpose::AdhocReportConfig).to receive(:new)
                                                .with(nil, 'sql')
                                                .and_return(@mock_report)

          expect(@mock_report).to receive(:add_filter)
                                 .with('version', '1.3.0')

          expect(@mock_report).to receive(:add_filter)
                                  .with('query', @expected_vulnerability_query)

          expect(@mock_report).to receive(:add_filter)
                                  .with('site', @mock_site_id)


          NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)

        end

        #it 'should download an adhoc report in CSV format with all the detected installed software ' do

        #end

        #it 'should download an adhoc report in CSV format with all the detected policy checks ' do

        #end
      end


  end
end

def get_mock_nexpose_client
  mock_nexpose_client = double(Nexpose::Connection)

  allow(mock_nexpose_client).to receive(:call).with(any_args).and_return({})

  allow(Nexpose::Connection).to receive(:new)
                             .and_return(mock_nexpose_client)

  mock_nexpose_client
end

def get_mock_nexpose_site
  mock_nexpose_site = double(Nexpose::Site)

  allow(mock_nexpose_site).to receive(:call).with(any_args).and_return({})

  allow(Nexpose::Site).to receive(:new)
                                .and_return(mock_nexpose_site)

  mock_nexpose_site
end

def get_mock_report
  mock_report = double(Nexpose::AdhocReportConfig)

  allow(mock_report).to receive(:call).with(any_args).and_return({})

  allow(Nexpose::AdhocReportConfig).to receive(:new)
                          .and_return(mock_report)

  mock_report
end