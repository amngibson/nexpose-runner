require 'nexpose-runner/constants'
require 'nexpose'

module NexposeRunner
  module Scan
    def Scan.start(connection_url, username, password)
      Nexpose::Connection.new connection_url, username, password

    end
  end
end
