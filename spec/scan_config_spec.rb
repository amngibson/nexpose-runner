require 'nexpose-runner/scan_run_description'
require 'yaml'

file_path = 'config/scan.yml'
describe 'scan_user_config_file_tests' do
  if File.file?('config/scan.yml')
    File.rename('config/scan.yml','config/scan.yml.bak')
  end

  describe 'start' do
    before(:each) do
      config_file = File.new(file_path, 'w')
      config_file.puts("connection_url: 'mydomain.wat'")
      config_file.puts("ip_addresses: ''")
      config_file.close
      @scan_run_description = ScanRunDescription.new({})
    end

    after(:each) do
      File.delete(file_path) if File.exist?(file_path)
    end

    it 'should get configuration from the config/scan.yaml when provided' do
      expect(@scan_run_description.connection_url).to eq('mydomain.wat')
    end
  end

  if File.file?('config/scan.yml.bak')
    File.rename('config/scan.yml.bak', 'config/scan.yml')
  end

end

describe 'scan_default_config_tests' do
  if File.file?('config/scan.yml')
    File.rename('config/scan.yml', 'config/scan.yml.bak')
  end

  describe 'start' do
    before(:each) do
      @options = {
        'connection_url' => 'foo.bar',
        'ip_addresses' => ''
      }
      @scan_run_description = ScanRunDescription.new(@options)
    end

    it 'should get configuration from the command line options' do
      expect(@scan_run_description.connection_url).to eq('foo.bar')
    end
  end

  if File.file?('config/scan.yml.bak')
    File.rename('config/scan.yml.bak', 'config/scan.yml')
  end

end
