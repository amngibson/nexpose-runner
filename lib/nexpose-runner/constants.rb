module CONSTANTS
  REQUIRED_CONNECTION_URL_MESSAGE = 'OOPS! Looks like you forgot to give me the URL/IP address to your Nexpose Server'
  REQUIRED_USERNAME_MESSAGE = 'OOPS! Looks like you forgot to give me a username to login to Nexpose with'
  REQUIRED_PASSWORD_MESSAGE = 'OOPS! Looks like you forgot to give me a password to login to Nexpose with'
  REQUIRED_SITE_NAME_MESSAGE = 'OOPS! Looks like you forgot to give me a Nexpose Site Name'
  REQUIRED_IP_ADDRESS_MESSAGE = 'OOPS! Looks like you forgot to give me an IP Address to scan'
  REQUIRED_SCAN_TEMPLATE_MESSAGE = 'OOPS! Looks like you forgot to give me a Scan Template to use'
  VULNERABILITY_FOUND_MESSAGE = '---------All YOUR BASE ARE BELONG TO US---------------\nVulnerabilities were found, breaking build'
  DEFAULT_PORT = '3780'
  VULNERABILITY_REPORT_NAME = 'nexpose-vulnerability-report.csv'
  SOFTWARE_REPORT_NAME = 'nexpose-software-report.csv'
  POLICY_REPORT_NAME = 'nexpose-policy-report.csv'

  AUDIT_REPORT_FILE_NAME = 'nexpose-audit-report.html'
  AUDIT_REPORT_NAME = 'audit-report'
  AUDIT_REPORT_FORMAT = 'html'

  XML_REPORT_FILE_NAME = 'nexpose-xml-report.xml'
  XML_REPORT_NAME = 'audit-report'
  XML_REPORT_FORMAT = 'raw-xml'

  VULNERABILITY_REPORT_QUERY = 'SELECT DISTINCT
                                  ip_address,
                                  title,
                                  date_published,
                                  severity,
                                  summary,
                                  fix
                                FROM fact_asset_scan_vulnerability_finding
                                JOIN dim_asset USING (asset_id)
                                JOIN dim_vulnerability USING (vulnerability_id)
                                JOIN dim_vulnerability_solution USING (vulnerability_id)
                                JOIN dim_solution_highest_supercedence USING (solution_id)
                                JOIN dim_solution ds ON superceding_solution_id = ds.solution_id'

  SOFTWARE_REPORT_QUERY = 'SELECT
                             dsi.name,
                             da.ip_address,
                             da.host_name,
                             dos.description,
                             dht.description,
                             ds.vendor,
                             ds.name,
                             ds.version
                           FROM dim_asset da
                           JOIN dim_operating_system dos USING (operating_system_id)
                           JOIN dim_host_type dht USING (host_type_id)
                           JOIN dim_asset_software das USING (asset_id)
                           JOIN dim_software ds USING (software_id)
                           JOIN dim_site_asset dsa USING (asset_id)
                           JOIN dim_site dsi USING (site_id)
                           ORDER BY
                            da.ip_address,
                            ds.vendor,
                            ds.name'

  POLICY_REPORT_QUERY = 'SELECT
                           fapr.compliance,
                           dpr.title,
                           dpr.description,
                           da.ip_address,
                           dp.title,
                           dp.benchmark_name,
                           dp.category,
                           dpr.scope,
                           fapr.proof
                         FROM fact_asset_policy_rule fapr
                         LEFT JOIN dim_policy dp on dp.policy_id = fapr.policy_id
                         LEFT JOIN dim_policy_rule dpr on dpr.policy_id = fapr.policy_id and fapr.rule_id = dpr.rule_id
                         LEFT JOIN dim_asset da on da.asset_id = fapr.asset_id
                         ORDER BY da.ip_address'
end
