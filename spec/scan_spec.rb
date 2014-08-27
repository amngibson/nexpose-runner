require 'nexpose-runner/scan'

class GenericObj
  attr_accessor :id
end

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
      @expected_software_query = 'SELECT
                                  dsi.name,
                                      da.ip_address,
                                      da.host_name,
                                      dos.description,
                                      dht.description,
                                      ds.vendor,
                                      ds.name,
                                      ds.version
                                  FROM dim_asset da
                                  JOIN dim_operating_system dos USING (operating_system_id)
                                  JOIN dim_host_type dht USING (host_type_id)
                                  JOIN dim_asset_software das USING (asset_id)
                                  JOIN dim_software ds USING (software_id)
                                  JOIN dim_site_asset dsa USING (asset_id)
                                  JOIN dim_site dsi USING (site_id)
                                  ORDER BY
                                  da.ip_address,
                                      ds.vendor,
                                      ds.name'
      @expected_policy_query = 'SELECT
                                 fapr.compliance,
                                 dpr.title,
                                 dpr.description,
                                 da.ip_address,
                                 dp.title,
                                 dp.benchmark_name,
                                 dp.category,
                                 dpr.scope,
                                 fapr.proof
                               FROM fact_asset_policy_rule fapr
                               LEFT JOIN dim_policy dp on dp.policy_id = fapr.policy_id
                               LEFT JOIN dim_policy_rule dpr on dpr.policy_id = fapr.policy_id and fapr.rule_id = dpr.rule_id
                               LEFT JOIN dim_asset da on da.asset_id = fapr.asset_id
                               ORDER BY da.ip_address'
      @mock_scan_id = '12'
      @mock_site_id = '1'
      @mock_nexpose_client = get_mock_nexpose_client
      @mock_nexpose_site = get_mock_nexpose_site
      @mock_report = get_mock_report
      @mock_report_vuln = get_mock_report
      @mock_report_software = get_mock_report
      @mock_vuln_report = 'ip_address,title,date_published,severity,summary,fix
                            172.31.32.180,Database Open Access,2010-01-01,Severe,Restrict database access,"
                            <p>
                            <p>
                            Configure the database server to only allow access to trusted systems.
                            For example, the PCI DSS standard requires you to place the database in an
                            internal network zone, segregated from the DMZ
                            </p></p>"
                            172.31.32.180,MySQL Obsolete Version,2007-07-25,Critical,Upgrade to the latest version of Oracle MySQL,"
                            <p>Download and apply the upgrade from:
                            <a href=""http://dev.mysql.com/downloads/mysql"">http://dev.mysql.com/downloads/mysql</a></p>'

      @mock_software_report = 'name,ip_address,host_name,description,description,vendor,name,version
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,MAKEDEV,3.24-6.el6
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,acl,2.2.49-6.el6
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,acpid,1.0.10-2.1.el6
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,attr,2.4.44-7.el6
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,audit,2.2-4.el6_5
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,audit-libs,2.2-4.el6_5
                              my_cool_software_build-28,10.5.0.15,,CentOS Linux 6.5,Virtual Machine,Linux,authconfig,6.1.12-13.el6'

      @mock_policy_report = 'compliance,title,description,ip_address,title,benchmark_name,category,scope,proof
                            false,Create Separate Partition for /tmp,The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.,10.0.39.104,CIS CentOS 6 CentOS Level 1,centos_6_benchmark,Custom Policies,Custom,"Based on the following 2 results: * Based on the following 1 results: * * At least one specified RPM Package Information entry must match the given criteria. At least one evaluation must pass.<Table TableTitle=""""><tr RowTitle="""">centos-releasePASS * * At least one specified Text File Content entry must match the given criteria. At least one evaluation must pass.<Table TableTitle=""""><tr RowTitle=""Path:/etc/fstab	Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$"">/etc/fstab<Table TableTitle=""""><tr RowTitle="""">Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$<td width=""40"">FAIL<Table TableTitle=""""><tr RowTitle="""">Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$<td width=""40"">FAIL<Table TableTitle=""""><tr RowTitle="""">Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$<td width=""40"">FAIL<Table TableTitle=""""><tr RowTitle="""">Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$<td width=""40"">FAIL<Table TableTitle=""""><tr RowTitle="""">Pattern:^[\s]*[\S][\s]([\S])[\s][\S][\s][\S][\s][\S][\s][\S]$<td width=""40"">FAIL"
                            false,Set nodev option for /tmp Partition,The nodev mount option specifies that the filesystem cannot contain special devices.,10.0.39.104,CIS CentOS 6 CentOS Level 1,centos_6_benchmark,Custom Policies,Custom,"Based on the following 2 results: * Based on the following 1 results: * * At least one specified RPM Package Information entry must match the given criteria. At least one evaluation must pass.<Table TableTitle=""""><tr RowTitle="""">centos-releasePASS * * At least one specified Text File Content entry must match the given criteria. At least one evaluation must pass.<Table TableTitle=""""><tr RowTitle="""">The specified Text File Content entry was not found based on given criteria."
                            '
      @mock_vuln_report_name = 'nexpose-vulnerability-report.csv'
      @mock_software_report_name = 'nexpose-software-report.csv'
      @mock_policy_report_name = 'nexpose-policy-report.csv'
    end

      it 'should create a session with the nexpose server' do

        obj = GenericObj.new
        obj.id = @mock_scan_id

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

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return(obj)

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

        expect(@mock_report).to receive(:generate).with(@mock_nexpose_client).and_return(@mock_vuln_report)

        expect(CSV).to receive(:parse).with(@mock_vuln_report.chomp, {:headers => :first_row})

        expect(CSV).to receive(:open).with(@mock_vuln_report_name, 'w')


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
        obj = GenericObj.new
        obj.id = @mock_scan_id

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

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return(obj)

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

        expect(@mock_report).to receive(:generate).with(@mock_nexpose_client).and_return(@mock_vuln_report)

        expect(CSV).to receive(:parse).with(@mock_vuln_report.chomp, {:headers => :first_row})

        expect(CSV).to receive(:open).with(@mock_vuln_report_name, 'w')

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

        obj = GenericObj.new
        obj.id = @mock_scan_id

        expect(@mock_nexpose_client).to receive(:login)
                                        .and_return(true)

        expect(Nexpose::Site).to receive(:new)
                                       .with(@expected_site_name, @expected_scan_template)
                                       .and_return(@mock_nexpose_site)

        expect(@mock_nexpose_site).to receive(:add_ip)
                                      .with(@expected_ip)

        expect(@mock_nexpose_site).to receive(:save)
                                      .with(@mock_nexpose_client)

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return(obj)

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

        expect(@mock_report).to receive(:generate).with(@mock_nexpose_client).and_return(@mock_vuln_report)

        expect(CSV).to receive(:parse).with(@mock_vuln_report.chomp, {:headers => :first_row})

        expect(CSV).to receive(:open).with(@mock_vuln_report_name, 'w')

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
      end

      it 'should add the supplied ip address to the newly created site' do
        obj = GenericObj.new
        obj.id = @mock_scan_id

        expect(@mock_nexpose_client).to receive(:login)
                                        .and_return(true)

        expect(Nexpose::Site).to receive(:new)
                                 .with(@expected_site_name, @expected_scan_template)
                                 .and_return(@mock_nexpose_site)

        expect(@mock_nexpose_site).to receive(:add_ip)
                                .with(@expected_ip)

        expect(@mock_nexpose_site).to receive(:save)
                                      .with(@mock_nexpose_client)

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return(obj)

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

        expect(@mock_report).to receive(:generate).with(@mock_nexpose_client).and_return(@mock_vuln_report)

        expect(CSV).to receive(:parse).with(@mock_vuln_report.chomp, {:headers => :first_row})

        expect(CSV).to receive(:open).with(@mock_vuln_report_name, 'w')

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
      end

      it 'should save the new site configuration' do
        obj = GenericObj.new
        obj.id = @mock_scan_id

        expect(@mock_nexpose_client).to receive(:login)
                                        .and_return(true)

        expect(Nexpose::Site).to receive(:new)
                                 .with(@expected_site_name, @expected_scan_template)
                                 .and_return(@mock_nexpose_site)

        expect(@mock_nexpose_site).to receive(:add_ip)
                                      .with(@expected_ip)

        expect(@mock_nexpose_site).to receive(:save)
                                      .with(@mock_nexpose_client)

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return(obj)

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

        expect(@mock_report).to receive(:generate).with(@mock_nexpose_client).and_return(@mock_vuln_report)

        expect(CSV).to receive(:parse).with(@mock_vuln_report.chomp, {:headers => :first_row})

        expect(CSV).to receive(:open).with(@mock_vuln_report_name, 'w')

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
      end

      it 'should initiate a scan' do
        obj = GenericObj.new
        obj.id = @mock_scan_id

        expect(@mock_nexpose_client).to receive(:login)
                                        .and_return(true)

        expect(Nexpose::Site).to receive(:new)
                                 .with(@expected_site_name, @expected_scan_template)
                                 .and_return(@mock_nexpose_site)

        expect(@mock_nexpose_site).to receive(:add_ip)
                                      .with(@expected_ip)

        expect(@mock_nexpose_site).to receive(:save)
                                      .with(@mock_nexpose_client)

        expect(@mock_nexpose_site).to receive(:scan)
                                      .with(@mock_nexpose_client)
                                      .and_return(obj)

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

        expect(@mock_report).to receive(:generate).with(@mock_nexpose_client).and_return(@mock_vuln_report)

        expect(CSV).to receive(:parse).with(@mock_vuln_report.chomp, {:headers => :first_row})

        expect(CSV).to receive(:open).with(@mock_vuln_report_name, 'w')

        NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
      end

      describe 'wait for the Nexpose Scan to complete' do
        before(:each) do

          obj = GenericObj.new
          obj.id = @mock_scan_id

          expect(@mock_nexpose_client).to receive(:login)
                                          .and_return(true)

          expect(Nexpose::Site).to receive(:new)
                                   .with(@expected_site_name, @expected_scan_template)
                                   .and_return(@mock_nexpose_site)

          expect(@mock_nexpose_site).to receive(:add_ip)
                                        .with(@expected_ip)

          expect(@mock_nexpose_site).to receive(:save)
                                        .with(@mock_nexpose_client)

          expect(@mock_nexpose_site).to receive(:scan)
                                        .with(@mock_nexpose_client)
                                        .and_return(obj)

          expect(Nexpose::AdhocReportConfig).to receive(:new)
                                                .with(nil, 'sql')
                                                .and_return(@mock_report)

          expect(@mock_report).to receive(:add_filter)
                                  .with('version', '1.3.0')

          expect(@mock_report).to receive(:add_filter)
                                  .with('query', @expected_vulnerability_query)

          expect(@mock_report).to receive(:add_filter)
                                  .with('site', @mock_site_id)

          expect(@mock_report).to receive(:generate).with(@mock_nexpose_client).and_return(@mock_vuln_report)

          expect(CSV).to receive(:parse).with(@mock_vuln_report.chomp, {:headers => :first_row})

          expect(CSV).to receive(:open).with(@mock_vuln_report_name, 'w')

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

          obj = GenericObj.new
          obj.id = @mock_scan_id


          expect(@mock_nexpose_client).to receive(:login)
                                          .and_return(true)

          expect(Nexpose::Site).to receive(:new)
                                   .with(@expected_site_name, @expected_scan_template)
                                   .and_return(@mock_nexpose_site)

          expect(@mock_nexpose_site).to receive(:add_ip)
                                        .with(@expected_ip)

          expect(@mock_nexpose_site).to receive(:save)
                                        .with(@mock_nexpose_client)

          expect(@mock_nexpose_site).to receive(:scan)
                                        .with(@mock_nexpose_client)
                                        .and_return(obj)

          expect(@mock_nexpose_client).to receive(:scan_status)
                                          .with(@mock_scan_id)

        end

        it 'should generate, download, and parse an adhoc report in CSV format with all the detected vulnerabilities ' do

          expect(Nexpose::AdhocReportConfig).to receive(:new)
                                                .with(nil, 'sql')
                                                .and_return(@mock_report_vuln)

          expect(@mock_report_vuln).to receive(:add_filter)
                                 .with('version', '1.3.0')

          expect(@mock_report_vuln).to receive(:add_filter)
                                  .with('query', @expected_vulnerability_query)

          expect(@mock_report_vuln).to receive(:add_filter)
                                  .with('site', @mock_site_id)

          expect(@mock_report_vuln).to receive(:generate).with(@mock_nexpose_client).and_return(@mock_vuln_report)

          expect(CSV).to receive(:parse).with(@mock_vuln_report.chomp, {:headers => :first_row})

          expect(CSV).to receive(:open).with(@mock_vuln_report_name, 'w')



          NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)

        end


        # it 'should generate, download, and parse an adhoc report in CSV format with all the detected software ' do
        #
        #   expect(Nexpose::AdhocReportConfig).to receive(:new)
        #                                         .with(nil, 'sql')
        #                                         .and_return(@mock_report_software).
        #
        #   expect(@mock_report_software).to receive(:add_filter)
        #                                    .with('version', '1.3.0')
        #
        #   expect(@mock_report_software).to receive(:add_filter)
        #                                    .with('query', @expected_software_query)
        #
        #   expect(@mock_report_software).to receive(:add_filter)
        #                                    .with('site', @mock_site_id)
        #
        #   expect(@mock_report_software).to receive(:generate).with(@mock_nexpose_client).and_return(@mock_software_report)
        #
        #   expect(CSV).to receive(:parse).with(@mock_software_report.chomp, {:headers => :first_row})
        #
        #   expect(CSV).to receive(:open).with(@mock_software_report_name, 'w')
        #
        #
        #   NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)
        #
        # end
        #
        # it 'should generate, download, and parse an adhoc report in CSV format with all the detected policies ' do
        #
        #   expect(Nexpose::AdhocReportConfig).to receive(:new)
        #                                         .with(nil, 'sql')
        #                                         .and_return(@mock_report)
        #
        #   expect(@mock_report).to receive(:add_filter)
        #                           .with('version', '1.3.0')
        #
        #   expect(@mock_report).to receive(:add_filter)
        #                           .with('query', @expected_policy_query)
        #
        #   expect(@mock_report).to receive(:add_filter)
        #                           .with('site', @mock_site_id)
        #
        #   expect(@mock_report).to receive(:generate).with(@mock_nexpose_client).and_return(@mock_policy_report)
        #
        #   expect(CSV).to receive(:parse).with(@mock_policy_report.chomp, {:headers => :first_row})
        #
        #   expect(CSV).to receive(:open).with(@mock_policy_report_name, 'w')
        #
        #
        #   NexposeRunner::Scan.start(@expected_connection, @expected_username, @expected_password, @expected_port, @expected_site_name, @expected_ip, @expected_scan_template)

        #end

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

  obj = GenericObj.new
  obj.id = @mock_scan_id

  allow(mock_nexpose_site).to receive(:scan)
                          .and_return(obj)

  allow(mock_nexpose_site).to receive(:id)
                          .and_return(@mock_site_id)

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