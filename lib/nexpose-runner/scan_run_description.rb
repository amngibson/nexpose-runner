require 'yaml'

class ScanRunDescription
  attr_accessor :connection_url, :username, :password, :port, :site_name, :ip_addresses, :scan_template, :engine
  @@port_value = ''
  @@ip_addresses = ''

  def initialize(options)
    if File.file?('config/scan.yml')
      options = YAML.load_file('config/scan.yml')
    end

    self.connection_url = options['connection_url']
    self.username =  options['username']
    self.password = options['password']
    @@port_value = options['port']
    self.site_name = options['site_name']
    self.ip_addresses = options['ip_addresses']
    self.scan_template = options['scan_template']
    self.engine = options['engine']
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

  def ip_addresses=(value)
    @@ip_addresses = value.split(',')
  end

  def ip_addresses
    @@ip_addresses
  end

  def get_value(value_to_check, default)
    (value_to_check.nil? || value_to_check.empty?) ? default : value_to_check
  end
end
