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

      site = create_site(run_details, nsc)

      start_scan(nsc, site)

      reports = generate_reports(nsc, site)

      verify_run(reports[0])
    end

    def self.generate_reports(nsc, site)
      vulnerbilities = generate_report(CONSTANTS::VULNERABILITY_REPORT_QUERY, site.id, nsc)
      generate_csv(vulnerbilities, CONSTANTS::VULNERABILITY_REPORT_NAME)

      software = generate_report(CONSTANTS::SOFTWARE_REPORT_QUERY, site.id, nsc)
      generate_csv(software, CONSTANTS::SOFTWARE_REPORT_NAME)

      policies = generate_report(CONSTANTS::POLICY_REPORT_QUERY, site.id, nsc)
      generate_csv(policies, CONSTANTS::POLICY_REPORT_NAME)

      [vulnerbilities, software, policies]
    end

    def self.verify_run(vulnerabilities)
      raise StandardError, CONSTANTS::VULNERABILITY_FOUND_MESSAGE if vulnerabilities.count > 0
    end

    def self.start_scan(nsc, site)
      scan = site.scan nsc

      begin
        sleep(3)
        status = nsc.scan_status(scan.id)
      end while status == Nexpose::Scan::Status::RUNNING
    end

    def self.create_site(run_details, nsc)
      site = Nexpose::Site.new run_details.site_name, run_details.scan_template
      site.add_ip run_details.ip_address
      site.save nsc
      site
    end

    def self.get_new_nexpose_connection(run_details)
      nsc = Nexpose::Connection.new run_details.connection_url, run_details.username, run_details.password, run_details.port
      nsc.login
      nsc
    end

    def self.generate_report(sql, site, nsc)
      report = Nexpose::AdhocReportConfig.new(nil, 'sql')
      report.add_filter('version', '1.3.0')
      report.add_filter('query', sql)
      report.add_filter('site', site)
      report_output = report.generate(nsc)
      CSV.parse(report_output.chomp, {:headers => :first_row})
    end

    def self.generate_csv(csv_output, name)
      CSV.open(name, 'w') do |csv_file|
        csv_file << csv_output.headers
        csv_output.each do |row|
          csv_file << row
        end
      end
    end
  end
end
