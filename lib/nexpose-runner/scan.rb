require 'nexpose'
require 'csv'
require 'nexpose-runner/constants'
require 'nexpose-runner/scan_run_description'


module NexposeRunner
  module Scan
    def Scan.start(connection_url, username, password, port, site_name, ip_address, scan_template)

      run_details = ScanRunDescription.new connection_url, username, password, port, site_name, ip_address, scan_template
      run_details.verify

      nsc = get_new_nexpose_connection(run_details)

      site = create_site(ip_address, nsc, scan_template, site_name)

      start_scan(nsc, site)

      generate_reports(nsc, site)

    end

    def self.generate_reports(nsc, site)
      generate_report(CONSTANTS::VULNERABILITY_REPORT_QUERY, CONSTANTS::VULNERABILITY_REPORT_NAME, site.id, nsc)
      #generate_report(CONSTANTS::SOFTWARE_REPORT_QUERY, CONSTANTS::SOFTWARE_REPORT_NAME, site.id, nsc)
      #generate_report(CONSTANTS::POLICY_REPORT_QUERY, CONSTANTS::POLICY_REPORT_NAME, site.id, nsc)
    end

    def self.start_scan(nsc, site)
      scan = site.scan nsc

      begin
        sleep(3)
        status = nsc.scan_status(scan.id)
      end while status == Nexpose::Scan::Status::RUNNING
    end

    def self.create_site(ip_address, nsc, scan_template, site_name)
      site = Nexpose::Site.new site_name, scan_template
      site.add_ip ip_address
      site.save nsc
      site
    end

    def self.get_new_nexpose_connection(run_details)
      nsc = Nexpose::Connection.new run_details.connection_url, run_details.username, run_details.password, run_details.port
      nsc.login
      nsc
    end

    def self.generate_report(sql, name, site, nsc)

      report = Nexpose::AdhocReportConfig.new(nil, 'sql')
      report.add_filter('version', '1.3.0')
      report.add_filter('query', sql)
      report.add_filter('site', site)
      report_output = report.generate(nsc)
      csv_output = CSV.parse(report_output.chomp, {:headers => :first_row})
      CSV.open(name, 'w') do |csv_file|
        csv_file << csv_output.headers
        csv_output.each do |row|
          csv_file << row

        end
      end
    end
  end
end
