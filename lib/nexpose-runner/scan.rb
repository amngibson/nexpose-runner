require 'nexpose'
require 'csv'
require 'nexpose-runner/constants'
require 'nexpose-runner/scan_run_description'


module NexposeRunner
  module Scan
    def Scan.start(options)

      run_details = ScanRunDescription.new(options)
      run_details.verify

      nsc = get_new_nexpose_connection(run_details)

      site = create_site(run_details, nsc)

      start_scan(nsc, site, run_details)

      reports = generate_reports(nsc, site, run_details)

      verify_run(reports[0])
    end

    def self.generate_reports(nsc, site, run_details)
      puts "Scan complete for #{run_details.site_name}, Generating Vulnerability Report"
      vulnerbilities = generate_report(CONSTANTS::VULNERABILITY_REPORT_QUERY, site.id, nsc)
      generate_csv(vulnerbilities, CONSTANTS::VULNERABILITY_REPORT_NAME)

      puts "Scan complete for #{run_details.site_name}, Generating Software Report"
      software = generate_report(CONSTANTS::SOFTWARE_REPORT_QUERY, site.id, nsc)
      generate_csv(software, CONSTANTS::SOFTWARE_REPORT_NAME)

      puts "Scan complete for #{run_details.site_name}, Generating Policy Report"
      policies = generate_report(CONSTANTS::POLICY_REPORT_QUERY, site.id, nsc)
      generate_csv(policies, CONSTANTS::POLICY_REPORT_NAME)

      puts "Scan complete for #{run_details.site_name}, Generating Audit Report"
      generate_audit_report(site.id, nsc, CONSTANTS::AUDIT_REPORT_NAME)

      [vulnerbilities, software, policies]
    end

    def self.verify_run(vulnerabilities)

      raise StandardError, CONSTANTS::VULNERABILITY_FOUND_MESSAGE if vulnerabilities.count > 0

    end

    def self.start_scan(nsc, site, run_details)

      puts "Starting scan for #{run_details.site_name} using the #{run_details.scan_template} scan template"
      scan = site.scan nsc

      begin
        sleep(3)
        stats = nsc.scan_statistics(scan.id)
 	status = stats.status
	progress = stats.tasks.completed / stats.tasks.pending * 100
        puts "Current #{run_details.site_name} scan status: #{status.to_s} : #{progress.to_s}% completed"
      end while status == Nexpose::Scan::Status::RUNNING
    end

    def self.create_site(run_details, nsc)
      puts "Creating a nexpose site named #{run_details.site_name}"
      site = Nexpose::Site.new run_details.site_name, run_details.scan_template
      run_details.ip_addresses.each { |address|
          site.add_ip address
      }
      site.save nsc
      puts "Created site #{run_details.site_name} successfully with the following host(s) #{run_details.ip_addresses.join(', ')}"
      site
    end

    def self.get_new_nexpose_connection(run_details)
      nsc = Nexpose::Connection.new run_details.connection_url, run_details.username, run_details.password, run_details.port
      nsc.login
      puts 'Successfully logged into the Nexpose Server'
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

    def self.generate_audit_report(site, nsc, name)
      adhoc = Nexpose::AdhocReportConfig.new('audit-report', 'html', site)
      data = adhoc.generate(nsc)
      File.open(name, 'w') { |file| file.write(data) }
    end

    def self.generate_csv(csv_output, name)
      CSV.open(name, 'w') do |csv_file|
        csv_file << csv_output.headers
        csv_output.each do |row|
          csv_file << row
          if name == CONSTANTS::VULNERABILITY_REPORT_NAME
            puts '--------------------------------------'
            puts "IP: #{row[0]}"
            puts "Vulnerability: #{row[1]}"
            puts "Date Vulnerability was Published: #{row[2]}"
            puts "Severity: #{row[3]}"
            puts "Summary: #{row[4]}"
            puts '--------------------------------------'
          end
        end
      end
    end
  end
end
