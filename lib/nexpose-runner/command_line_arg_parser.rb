require 'optparse'

class CommandLineArgumentParser
  def self.parse(args)
    options = {}
    options['connection_url'] = ''
    options['exceptions_list_url'] = ''
    options['username'] = ''
    options['password'] = ''
    options['port'] = 0
    options['site_name'] = ''
    options['ip_addresses'] = ''
    options['scan_template'] = ''
    options['engine_id'] = ''
    options['cleanup'] = false
    options['gen-software-report'] = true
    options['gen-policy-report'] = true
    options['gen-xml-report'] = true
    options['gen-audit-report'] = true

    opt_parser = OptionParser.new do |opts|
      opts.banner = 'Usage: scan [options]'

      opts.separator ''
      opts.separator 'Specific options:'

      opts.on('--connection-url URL', 'Nexpose Url') do |url|
        options['connection_url'] = url
      end
      
      opts.on('--exceptions_list_url eURL', 'Vulnerability list URL') do |exceptions_list_url| 
              options['exceptions_list_url'] = exceptions_list_url
      end      
      opts.on('--username USERNAME', 'Nexpose Login Username') do |username|
        options['username'] = username
      end
      
      opts.on('--password PASSWORD', 'Nexpose Login Password') do |password|
        options['password'] = password
      end

      opts.on('--port PORT', 'Nexpose port') do |port|
        options['port'] = port
      end
      
      opts.on('--site-name NAME', 'Nexpose site name') do |sitename|
        options['site_name'] = sitename
      end
      
      opts.on('--ip-addresses IPS', 'Comma separated list of IP Addresses to scan') do |ips|
        options['ip_addresses'] = ips
      end
      
      opts.on('--scan-template-id TEMPLATE', 'Nexpose scan template to use') do |template|
        options['scan_template_id'] = template
      end
      
      opts.on('--engine-id ENGINE', 'Nexpose scan engine to use') do |engine|
        options['engine_id'] = engine
      end

      opts.on('--[no-]gen-policy-report', 'Enable/Disable the Policy report') do |gen_report|
        options['gen-policy-report'] = gen_report
      end
      opts.on('--[no-]gen-software-report', 'Enable/Disable the Software report') do |gen_report|
        options['gen-software-report'] = gen_report
      end
      opts.on('--[no-]gen-audit-report', 'Enable/Disable the Audit report') do |gen_report|
        options['gen-audit-report'] = gen_report
      end
      opts.on('--[no-]gen-xml-report', 'Enable/Disable the XML report') do |gen_report|
        options['gen-xml-report'] = gen_report
      end

      opts.on('--cleanup', 'Enables the deletion of assets created during the scan') do |cleanup|
        options['cleanup'] = cleanup
      end
    end

    opt_parser.parse!(args)
    options
  end
end
