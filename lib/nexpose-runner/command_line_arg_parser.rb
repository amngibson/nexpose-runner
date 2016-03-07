require 'optparse'

class CommandLineArgumentParser
  def self.parse(args)
    options = {}
    options['connection_url'] = ''
    options['username'] = ''
    options['password'] = ''
    options['port'] = 0
    options['site_name'] = ''
    options['ip_addresses'] = ''
    options['scan_template'] = ''
    options['engine'] = ''

    opt_parser = OptionParser.new do |opts|
      opts.banner = 'Usage: scan [options]'

      opts.separator ''
      opts.separator 'Specific options:'

      opts.on('--connection-url URL', 'Nexpose Url') do |url|
        options['connection_url'] = url
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
      
      opts.on('--scan-template TEMPLATE', 'Nexpose scan template to use') do |template|
        options['template'] = template
      end
      
      opts.on('--engine ENGINE', 'Nexpose scan engine to use') do |engine|
        options['engine'] = engine
      end
      
      opts.on('--exception-file EXCEPTIONS', 'Exception file to use for site level vulnerability exceptions') do |exceptions|
        options['exception_file'] = exceptions
      end
    end

    opt_parser.parse!(args)
    options
  end
end
