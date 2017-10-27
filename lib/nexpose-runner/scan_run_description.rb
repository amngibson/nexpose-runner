require 'yaml'
require 'nexpose-runner/command_line_arg_parser'

class ScanRunDescription
  attr_accessor :connection_url, :exceptions_list_url, :username, :password, :port, :site_name, :ip_addresses, :scan_template, :engine
  @@port_value = ''
  @@ip_addresses = []
  @@timeout = ''
  @@open_timeout =''
  exceptions_list_url_value = ''

  def initialize(options)
    if File.file?('config/scan.yml')
      options = YAML.load_file('config/scan.yml')
    elsif options.instance_of? Array
      options = CommandLineArgumentParser.parse(options)
    end

    self.connection_url = options['connection_url']
    @@exceptions_list_url_value = options['exceptions_list_url']
    self.username =  options['username']
    self.password = options['password']
    @@port_value = options['port']
    self.site_name = options['site_name']
    self.ip_addresses = options['ip_addresses']
    self.scan_template = options['scan_template']
    self.engine = options['engine']
    self.timeout = options['timeout']
    self.open_timeout = options['open_timeout']
  end

  def verify
    raise StandardError, CONSTANTS::REQUIRED_CONNECTION_URL_MESSAGE if connection_url.nil? || connection_url.empty?
    raise StandardError, CONSTANTS::REQUIRED_USERNAME_MESSAGE if username.nil? || username.empty?
    raise StandardError, CONSTANTS::REQUIRED_PASSWORD_MESSAGE if password.nil? || password.empty?
    raise StandardError, CONSTANTS::REQUIRED_SITE_NAME_MESSAGE if site_name.nil? || site_name.empty?
    raise StandardError, CONSTANTS::REQUIRED_IP_ADDRESS_MESSAGE if ip_addresses.length == 0
    raise StandardError, CONSTANTS::REQUIRED_SCAN_TEMPLATE_MESSAGE if scan_template.nil? || scan_template.empty?

  end

  def port=(value)
    @@port_value = value
  end

  def port
    get_value(@@port_value, CONSTANTS::DEFAULT_PORT)
  end

  def timeout=(value)
    @@timeout = value
  end

  def timeout
    get_value(@@timeout, CONSTANTS::DEFAULT_TIMEOUT)
  end

  def open_timeout=(value)
    @@open_timeout = value
  end

  def open_timeout
    get_value(@@open_timeout, CONSTANTS::DEFAULT_OPEN_TIMEOUT)
  end

  def exceptions_list_url=(value)
    @@exceptions_list_url_value = value
  end

  def exceptions_list_url
    get_value(@@exceptions_list_url_value, CONSTANTS::DEFAULT_EXCEPTIONS_URL)
  end

  def ip_addresses=(value)
    @@ip_addresses = value.split(',') unless value.nil?
  end

  def ip_addresses
    @@ip_addresses
  end

  def get_value(value_to_check, default)
    (value_to_check.nil? || value_to_check.empty?) ? default : value_to_check
  end
end
