require 'nexpose-runner/scan'
require 'nexpose-runner/constants'
require 'ostruct'

describe 'nexpose-runner' do

  if File.file?('config/exploit.yml')
    File.rename('config/exploit.yml', 'config/exploit.yml.bak')
  end

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
      @expected_ips = '10.5.0.15,10.5.0.20,10.5.0.35'
      @expected_scan_template = 'full-audit-widget-corp'
      @mock_scan_id = '12'
      @mock_site_id = '1'

      @mock_no_vuln_report = 'ip_address,title,date_published,severity,summary,fix'
      @mock_vuln_report = 'ip_address,title,date_published,severity,summary,fix
                            10.5.0.15,Database Open Access,2010-01-01,Severe,Restrict database access,<p><p>Configure the database server to only allow access to trusted systems. For example, the PCI DSS standard requires you to place the database in an internal network zone, segregated from the DMZ </p></p>
                            10.5.0.15.180,MySQL Obsolete Version,2007-07-25,Critical,Upgrade to the latest version of Oracle MySQL,<p>Download and apply the upgrade from: <a href=http://dev.mysql.com/downloads/mysql>http://dev.mysql.com/downloads/mysql</a></p>'.chomp

      @mock_software_report = 'name,ip_address,host_name,description,description,vendor,name,version
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,MAKEDEV,3.24-6.el6
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,acl,2.2.49-6.el6
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,acpid,1.0.10-2.1.el6
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,attr,2.4.44-7.el6
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,audit,2.2-4.el6_5
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,audit-libs,2.2-4.el6_5
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,authconfig,6.1.12-13.el6'.chomp

      @mock_policy_report = 'compliance,title,description,ip_address,title,benchmark_name,category,scope,proof
                            false,Create Separate Partition for /tmp,The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.,10.0.39.104,CIS CentOS 6 CentOS Level 1,centos_6_benchmark,Custom Policies,Custom,"Based on the following 2 results: * Based on the following 1 results: * * At least one specified RPM Package Information entry must match the given criteria. At least one evaluation must pass.<Table TableTitle=""""><tr RowTitle="""">centos-releasePASS * * At least one specified Text File Content entry must match the given criteria. At least one evaluation must pass.<Table TableTitle=""""><tr RowTitle=""Path:/etc/fstab	Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$"">/etc/fstab<Table TableTitle=""""><tr RowTitle="""">Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$<td width=""40"">FAIL<Table TableTitle=""""><tr RowTitle="""">Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$<td width=""40"">FAIL<Table TableTitle=""""><tr RowTitle="""">Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$<td width=""40"">FAIL<Table TableTitle=""""><tr RowTitle="""">Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$<td width=""40"">FAIL<Table TableTitle=""""><tr RowTitle="""">Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$<td width=""40"">FAIL"
                            false,Set nodev option for /tmp Partition,The nodev mount option specifies that the filesystem cannot contain special devices.,10.0.39.104,CIS CentOS 6 CentOS Level 1,centos_6_benchmark,Custom Policies,Custom,"Based on the following 2 results: * Based on the following 1 results: * * At least one specified RPM Package Information entry must match the given criteria. At least one evaluation must pass.<Table TableTitle=""""><tr RowTitle="""">centos-releasePASS * * At least one specified Text File Content entry must match the given criteria. At least one evaluation must pass.<Table TableTitle=""""><tr RowTitle="""">The specified Text File Content entry was not found based on given criteria."
                            '.chomp


      @mock_scan = get_mock_scan
      @mock_scan_summary = get_mock_scan_summary
      @mock_nexpose_client = get_mock_nexpose_client
      @mock_nexpose_site = get_mock_nexpose_site
      @mock_report = get_mock_report


      @options = {
        'connection_url' => @expected_connection,
        'username' => @expected_username,
        'password' => @expected_password,
        'port' => @expected_port,
        'site_name' => @expected_site_name,
        'ip_addresses' => @expected_ips,
        'scan_template' => @expected_scan_template
      }

    end

      it 'should create a session with the nexpose server' do
        expect(Nexpose::Connection).to receive(:new)
                                    .with(@options['connection_url'],
                                          @options['username'], 
                                          @options['password'], 
                                          @options['port'])
                                    .and_return(@mock_nexpose_client)

        expect(@mock_nexpose_client).to receive(:login)
                                    .and_return(true)

        NexposeRunner::Scan.start(@options)
      end

      it 'should throw an error if no connection url is passed' do
        options = @options.clone
        options['connection_url'] = nil
        expect { 
          NexposeRunner::Scan.start(options) 
        }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me the URL/IP address to your Nexpose Server')
      end

      it 'should throw an error if no username is passed' do
        options = @options.clone
        options['username'] = nil
        expect { 
          NexposeRunner::Scan.start(options) 
        }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a username to login to Nexpose with')
      end

      it 'should throw an error if no password is passed' do
        options = @options.clone
        options['password'] = nil
        expect { 
          NexposeRunner::Scan.start(options) 
        }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a password to login to Nexpose with')
      end

      it 'should throw an error if no site name is passed' do
        options = @options.clone
        options['site_name'] = nil
        expect { 
          NexposeRunner::Scan.start(options) 
        }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a Nexpose Site Name')
      end

      it 'should throw an error if no ip address is passed' do
        options = @options.clone
        options['ip_addresses'] = '';
        expect { 
          NexposeRunner::Scan.start(options) 
        }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me an IP Address to scan')
      end

      it 'should throw an error if no scan template is passed' do
        options = @options.clone
        options['scan_template'] = nil
        expect { 
          NexposeRunner::Scan.start(options) 
        }.to raise_error(StandardError, 'OOPS! Looks like you forgot to give me a Scan Template to use')
      end

      it 'should use 3780 as default if port is empty string' do
        expect(Nexpose::Connection).to receive(:new)
                                       .with(@options['connection_url'], 
                                             @options['username'], 
                                             @options['password'], 
                                             '3780')
                                       .and_return(@mock_nexpose_client)


        run_options = @options.clone
        run_options['port'] = ''
        NexposeRunner::Scan.start(run_options)
      end

      it 'should create a new Nexpose site with the supplied site name and scan template' do
        expect(Nexpose::Site).to receive(:new)
                                       .with(@options['site_name'], @options['scan_template'])
                                       .and_return(@mock_nexpose_site)

        NexposeRunner::Scan.start(@options)
      end

      it 'should add the supplied ip address to the newly created site' do
        @expected_ips.split(',').each { |ip|
          expect(@mock_nexpose_site).to receive(:add_ip).with(ip)
        }
        NexposeRunner::Scan.start(@options)
      end

      it 'should save the new site configuration' do
        expect(@mock_nexpose_site).to receive(:save)
                                      .with(@mock_nexpose_client)

        NexposeRunner::Scan.start(@options)
      end

      it 'should initiate a scan' do
        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return(@mock_scan)

        NexposeRunner::Scan.start(@options)
      end

      describe 'wait for the Nexpose Scan to complete' do
        it 'should call to check the status of the scan' do
          expect(@mock_nexpose_client).to receive(:scan_statistics).with(@mock_scan_id)
  
          NexposeRunner::Scan.start(@options)
        end
  
        it 'should call to check the status until it is not running' do
          expect(@mock_scan_summary).to receive(:status)
                                      .and_return(Nexpose::Scan::Status::RUNNING)
                                      .exactly(3).times
                                      .ordered
  
          expect(@mock_scan_summary).to receive(:status)
                                      .and_return(Nexpose::Scan::Status::FINISHED)
                                      .once
                                      .ordered
  
          NexposeRunner::Scan.start(@options)
        end
  
        it 'should sleep for 3 seconds if the status is still running' do
          expect(@mock_scan_summary).to receive(:status)
                                      .and_return(Nexpose::Scan::Status::RUNNING)
                                      .exactly(3).times
                                      .ordered
  
          expect(@mock_scan_summary).to receive(:status)
                                      .and_return(Nexpose::Scan::Status::FINISHED)
                                      .once
                                      .ordered

          expect(NexposeRunner::Scan).to receive(:sleep).with(3).exactly(4).times
  
          NexposeRunner::Scan.start(@options)
        end
      end

      describe 'it should create reports' do
      it 'should generate, download, and parse an adhoc reports for Vulnerability, Software, and Policies' do
          expect(Nexpose::AdhocReportConfig).to receive(:new)
                                                .with(nil, 'sql')
                                                .and_return(@mock_report)

          expect_report_to_be_called_with(CONSTANTS::VULNERABILITY_REPORT_NAME, CONSTANTS::VULNERABILITY_REPORT_QUERY, @mock_vuln_report)
          expect_report_to_be_called_with(CONSTANTS::SOFTWARE_REPORT_NAME, CONSTANTS::SOFTWARE_REPORT_QUERY, @mock_software_report)
          expect_report_to_be_called_with(CONSTANTS::POLICY_REPORT_NAME, CONSTANTS::POLICY_REPORT_QUERY, @mock_policy_report)

          expect(Nexpose::AdhocReportConfig).to receive(:new)
                                                .with(CONSTANTS::AUDIT_REPORT_NAME, CONSTANTS::AUDIT_REPORT_FORMAT, @mock_site_id)
                                                .and_return(@mock_report)
        
          expect(Nexpose::AdhocReportConfig).to receive(:new)
                                                .with(CONSTANTS::XML_REPORT_NAME, CONSTANTS::XML_REPORT_FORMAT, @mock_site_id)
                                                .and_return(@mock_report)

          expect_template_report_to_be_called_with(CONSTANTS::AUDIT_REPORT_FILE_NAME)
          expect_template_report_to_be_called_with(CONSTANTS::XML_REPORT_FILE_NAME)
          
          expect { 
            NexposeRunner::Scan.start(@options) 
          }.to raise_error(StandardError, CONSTANTS::VULNERABILITY_FOUND_MESSAGE)
      end
    end

      it 'should throw exception if vulnerability exists' do
      expect_report_to_be_called_with(CONSTANTS::VULNERABILITY_REPORT_NAME, CONSTANTS::VULNERABILITY_REPORT_QUERY, @mock_vuln_report)

      expect { 
        NexposeRunner::Scan.start(@options) 
      }.to raise_error(StandardError, CONSTANTS::VULNERABILITY_FOUND_MESSAGE)
    end
  end

  if File.file?('config/exploit.yml.bak')
    File.rename('config/exploit.yml.bak', 'config/exploit.yml')
  end
end

def expect_report_to_be_called_with(report_name, report_query, report_response)
  expect(@mock_report).to receive(:add_filter)
                          .with('version', '1.3.0')

  expect(@mock_report).to receive(:add_filter)
                          .with('query', report_query).ordered

  expect(@mock_report).to receive(:add_filter)
                          .with('site', @mock_site_id)

  expect(@mock_report).to receive(:generate).with(@mock_nexpose_client).and_return(report_response).ordered

  expect(CSV).to receive(:open).with(report_name, 'w').ordered
end

def expect_template_report_to_be_called_with(report_file_name)
  expect(@mock_report).to receive(:generate).with(@mock_nexpose_client).ordered
  expect(File).to receive(:open).with(report_file_name, 'w').ordered
end

def get_mock_nexpose_client
  mock_nexpose_client = double(Nexpose::Connection)

  allow(mock_nexpose_client).to receive(:call).with(any_args).and_return({})

  allow(mock_nexpose_client).to receive(:scan_statistics)
                                 .with(@mock_scan_id)
				 .and_return(@mock_scan_summary)

  allow(mock_nexpose_client).to receive(:login)
                                  .and_return(true)

  allow(Nexpose::Connection).to receive(:new)
                             .and_return(mock_nexpose_client)

  mock_nexpose_client
end

def get_mock_scan_summary
  mock_scan_summary = double(Nexpose::ScanSummary)

  tasks = OpenStruct.new(:completed => 1, :pending => 1)
  allow(mock_scan_summary).to receive(:tasks).and_return(tasks)

  allow(mock_scan_summary).to receive(:status).and_return(
				Nexpose::Scan::Status::RUNNING, 
				Nexpose::Scan::Status::RUNNING,
 				Nexpose::Scan::Status::RUNNING, 
				Nexpose::Scan::Status::FINISHED)
  mock_scan_summary
end

def get_mock_nexpose_site
  mock_nexpose_site = double(Nexpose::Site)

  allow(mock_nexpose_site).to receive(:call).with(any_args).and_return({})

  allow(mock_nexpose_site).to receive(:scan)
                          .and_return(@mock_scan)

  allow(mock_nexpose_site).to receive(:id)
                          .and_return(@mock_site_id)

  @expected_ips.split(',').each { |ip|
    allow(mock_nexpose_site).to receive(:add_ip).with(ip)
  }

  allow(mock_nexpose_site).to receive(:save)
                                .with(@mock_nexpose_client)

  allow(mock_nexpose_site).to receive(:scan)
                                .with(@mock_nexpose_client)
                                .and_return(@mock_scan)

  allow(Nexpose::Site).to receive(:new)
                                .and_return(mock_nexpose_site)

  mock_nexpose_site
end

def get_mock_report
  mock_report = double(Nexpose::AdhocReportConfig)

  allow(mock_report).to receive(:call).with(any_args).and_return({})

  allow(mock_report).to receive(:add_filter)
                          .with(any_args)

  allow(mock_report).to receive(:add_filter)
                          .with(any_args)

  allow(mock_report).to receive(:add_filter)
                          .with(any_args)

  allow(mock_report).to receive(:generate).with(any_args)
                        .and_return(@mock_no_vuln_report)

  allow(Nexpose::AdhocReportConfig).to receive(:new)
                          .and_return(mock_report)

  allow(CSV).to receive(:open).with(any_args)
  allow(File).to receive(:open).with(any_args)

  mock_report
end

def get_mock_scan
  mock_scan = double(Nexpose::Scan)
  allow(mock_scan).to receive(:id).and_return(@mock_scan_id)
  mock_scan
end
