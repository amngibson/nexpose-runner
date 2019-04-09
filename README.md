# NexposeRunner::Scan

This is a ruby gem that basically wraps the nexpose-client gem. It was primarily created to automate scanning and reporting of dynamic hosts.

This gem will make a nexpose server connection, create a new site (if the site does not already exist), initiate a scan against the assets in the site, and generate a vulnerability report, software report, and policy compliance report.

Basically this gem allows you to attach Nexpose to your Continuous Delivery/Continuous Integration pipeline. Though it can be used for other purposes.

At the end of the scan it will generate 3 csv reports and save them in the directory where the script was executed from. It will also raise an exception if a vulnerability is detected. This is used to break the Continuous Delivery/Continuous integration build. You may add an exception list URL to prevent breaking the build.

## Installation

Add this line to your application's Gemfile:

    gem 'NexposeRunner'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install NexposeRunner

## Usage

This gem allows you to specify the Nexpose Server URL, Exceptions URL (optional), Nexpose Username, Nexpose Password, Nexpose Server Port (optional, defaults to 3780), Site Name, Target IP Address, Scan Template, Engine Number (optional) and Cleanup (optional). The 'Cleanup' option will delete the current site you are scanning once all scans have successfully been completed.

*NOTE:* If you use the "exceptions_list_url" parameter, please ensure you have proper authentication in place.

EXAMPLE:

    $ scan --connection test.com [--exceptions_list_url raw.github.com/exceptions.txt] --username username1 --password password1 [--port 443] --site-name myfirstsite --ip-addresses 192.168.1.10 --scan-template full-audit [--engine_id 2] [--cleanup] [--no-gen-policy-report] [--no-gen-software-report] [--no-gen-xml-report] [--no-gen-audit-report]

It is possible to use a YAML file to drive the configuration of this module.  An example configuration file is provided in config/scan.yml.example.  Simply copy it to config/scan.yml and modify it to work with your environment.

## Contributing

1. Fork it ( https://github.com/[my-github-username]/nexpose-scan/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
