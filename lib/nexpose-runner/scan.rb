require 'nexpose'
require 'csv'
require 'json'
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
      generate_template_report(nsc, site.id, CONSTANTS::AUDIT_REPORT_FILE_NAME, CONSTANTS::AUDIT_REPORT_NAME, CONSTANTS::AUDIT_REPORT_FORMAT)
      
      puts "Scan complete for #{run_details.site_name}, Generating Xml Report"
      generate_template_report(nsc, site.id, CONSTANTS::XML_REPORT_FILE_NAME, CONSTANTS::XML_REPORT_NAME, CONSTANTS::XML_REPORT_FORMAT)

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
        puts "Current #{run_details.site_name} scan status: #{status.to_s} -- PENDING: #{stats.tasks.pending.to_s} ACTIVE: #{stats.tasks.active.to_s} COMPLETED #{stats.tasks.completed.to_s}"
      end while status == Nexpose::Scan::Status::RUNNING
    end

    def self.create_site(run_details, nsc)
      puts "Creating a nexpose site named #{run_details.site_name}"
      site = Nexpose::Site.new run_details.site_name, run_details.scan_template
      run_details.ip_addresses.each { |address|
          site.add_ip address
      }
      if run_details.engine
        site.engine = run_details.engine
      end
      site.save nsc
      puts "Created site #{run_details.site_name} successfully with the following host(s) #{run_details.ip_addresses.join(', ')}"
      
      unless run_details.exception_file.nil? 
        create_exceptions(nsc, run_details.exception_file, site)
      end
      
      site
    end
    
    def self.create_exceptions(nsc, exceptions_file, site)
      file = File.read(exceptions_file)
      exceptions = JSON.parse(file)
      exceptions['exceptions'].each do |exception|
        exc = Nexpose::VulnException.new exception['id'], Nexpose::VulnException::Scope::SPECIFIC_INSTANCE_OF_SPECIFIC_ASSET, exception['reason']
        exc.asset_id = 0
        exc.port = 1030
        exc.save nsc
        exc.approve nsc
      end
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

    def self.generate_template_report(nsc, site, file_name, report_name, report_format)
      adhoc = Nexpose::AdhocReportConfig.new(report_name, report_format, site)
      data = adhoc.generate(nsc)
      File.open(file_name, 'w') { |file| file.write(data) }
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
