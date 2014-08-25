require 'nexpose-runner/constants'
require 'nexpose'

module NexposeRunner
  module Scan
    def Scan.start(connection_url, username, password)
      nsc = Nexpose::Connection.new connection_url, username, password
      nsc.login
    end
  end
end
