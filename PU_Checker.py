#!/usr/bin/env python

'''
Copyright (C)  2015, Apache Ambari
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
MIT License
Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.
GNU Lesser General Public License v1.3
Permission is granted to copy, distribute and/or modify this document
under the terms of the GNU Free Documentation License, Version 1.3
or any later version published by the Free Software Foundation;
with no Invariant Sections, no Front-Cover Texts, and no Back-Cover Texts.
A copy of the license is included in the section entitled "GNU Free Documentation License".
'''

'''
This script is provided as is with no guarantees.

It is meant to be used on clusters deployed with Ambari and using Ambari version 2.0.0 or higher,
in order to perform Pre-Upgrade checks.
As of this version, this script only supports MySQL and Postgres.
'''

# System imports
import sys
import os
import platform
import logging
import signal       # used to handle SIGINT and SIGTERM
import subprocess   # used to check if ambari-server is running
import re           # used to check if ambari-server is running when running regex on output
import json         # used to parse the json data



from optparse import OptionParser

Logger = logging.getLogger()

AMBARI_PROPERTIES_LOCATION = "/etc/ambari-server/conf/ambari.properties"
AMBARI_AGENT_INI = "/etc/ambari-agent/conf/ambari-agent.ini"

MIN_AMBARI_VERSION = "2.0.0"

class DB_TYPE:
  MYSQL = "MYSQL"
  POSTGRES = "POSTGRES"

class PUChecker:
  """
  Rolling Upgrade Magician analyzes the database to find and correct any issues.
  It is a terminal-driven application, that prompts the user to select options.
  """

  def __init__(self, argv):
    parser = OptionParser()
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False)

    (self.options, self.args) = parser.parse_args(argv)

    # Log to stdout
    logging_level = logging.DEBUG if self.options.verbose else logging.INFO
    Logger.setLevel(logging_level)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging_level)
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    Logger.addHandler(ch)

    # Handle terminations gracefully
    signal.signal(signal.SIGTERM, self.terminate)
    signal.signal(signal.SIGINT, self.terminate)

    self.print_usage()
    self.configure()

    # if not self.check_ambari_server_process_down():
    #   Logger.info("Ambari Server cannot be running while we make database updates. Please call \"ambari-server stop\" and try running this script again.")
    #   self.terminate()

    if not self.check_ambari_server_process_up():
      Logger.info("Ambari Server should be running to get the current status of cluster. Please call \"ambari-server start\" and try running this script again.")
      self.terminate()

    self.pre_upgrade_checks()

  def print_license(self):
    # LGPL License header
    license = "Permission is granted to copy, distribute and/or modify this document\n" \
              "under the terms of the GNU Free Documentation License, Version 1.3\n" \
              "or any later version published by the Free Software Foundation;\n" \
              "with no Invariant Sections, no Front-Cover Texts, and no Back-Cover Texts.\n" \
              "A copy of the license is included in the section entitled \"GNU Free Documentation License\".\n\n"
#    print(license)

  def print_usage(self):
    self.print_license()

    msg = "\n*********************************************************************\n" \
          "This script excutes a Pre-Upgrade checklist on your cluster\n" \
          "It assumes that you have Ambari {0} or higher.\n".format(MIN_AMBARI_VERSION) + \
          "IMPORTANT, this script must be ran from the host with Ambari Server.\n" \
          "*********************************************************************\n"
    Logger.info(msg)

  def terminate(self, signum=None, stack=None):
    """
    Exit gracefully, closing any option file handles or connections.
    It is important to use print statements instead of Logging statements in case that the logger is not yet
    initialized.
    :param signum: Usually SIGTERM, SIGTINT, or None (if user entered "q").
    :param stack: Stack trace
    """
    if signum:
      print("Caught termination signal {0}. Will exit gracefully.".format(signum))
    if hasattr(self, "cursor") or hasattr(self, "conn"):
      try:
        print("Will try to close database connection.")
        if hasattr(self, "cursor") and self.cursor:
          self.cursor.close()
        if hasattr(self, "conn") and self.conn:
          self.conn.close()
        print("Closed database connection successfully.")
      except Exception, e:
        print("Unable to close database connection. Error: {0}\n".format(e.message))
    sys.exit(0)

  def check_ambari_server_process_down(self):
    """
    Before running any DB commands, ensure that Ambari Server is not running.
    :return: Return True if ambari-server is not running, otherwise, False.
    """
    process_name = "ambari-server"
    output = self.__find_process(process_name)
    return re.search(process_name, output) is None

  def check_ambari_server_process_up(self):
    """
    To get the current cluster status, ensure that Ambari Server is running.
    :return: Return True if ambari-server is running, otherwise, False.
    """
    process_name = "ambari-server"
    output = self.__find_process(process_name)
    return re.search(process_name, output)

  def __find_process(self, process_name):
    ps = subprocess.Popen("ps -ef | grep {0} | grep -v grep".format(process_name), shell=True, stdout=subprocess.PIPE)
    output = ps.stdout.read()
    #Logger.debug("Checking if process {0} is running. Output: {1}.\n".format(process_name, output))
    ps.stdout.close()
    ps.wait()
    return output

  def check_java_version(self):
    ps = subprocess.Popen("ps -ef | grep -i ambari-server | grep -v grep | awk '{print $8}'", shell=True, stdout=subprocess.PIPE)
    psoutput = ps.stdout.read()
    ps.stdout.close()
    ps.wait()
    java_home = psoutput.rstrip().rsplit("/",2)[0]
    Logger.info("Java home\t{0}".format(java_home))

    sp = subprocess.Popen([java_home + "/bin/java", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    Logger.info("Java version\t{0}".format(sp.communicate()[1]))
    #print sp.wait()

    #TODO check and change the logic

    os.system("cp "+ java_home + "/jre/lib/security/local_policy.jar /tmp/")
    os.system("cd /tmp/;" + java_home + "/bin/jar xf /tmp/local_policy.jar default_local.policy")
    #check_jce = os.system("grep 'permission javax.crypto' /tmp/default_local.policy")
    cj = subprocess.Popen(["grep" ,"permission javax.crypto" ,"/tmp/default_local.policy"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    Logger.info("JCE\t{0}".format(cj.communicate()[0]))

    #Logger.info("JCE \t{0}\n".format(check_jce))

    '''
    jv = subprocess.Popen(psoutput.rstrip() + " -version", shell=True, stdout=subprocess.PIPE)
    output = jv.stdout.read()
    Logger.info("Java version\t{0}\n".format(output.rstrip()))
    jv.stdout.close()
    jv.wait()
    '''

  def configure(self):
    """
    Read configurations and ensure can connect to database.
    """
    # Defaults
    self.db_type = DB_TYPE.POSTGRES
    self.db_name = "ambari"
    self.db_user = "ambari"
    self.db_password = "bigdata"
    self.db_host = "localhost"
    self.db_url = None

    if os.path.exists(AMBARI_PROPERTIES_LOCATION):
      self.ambari_props = self.read_conf_file(AMBARI_PROPERTIES_LOCATION)

      if "server.jdbc.database" in self.ambari_props:
        self.db_type = self.ambari_props["server.jdbc.database"].upper()
      if "server.jdbc.database_name" in self.ambari_props:
        self.db_name = self.ambari_props["server.jdbc.database_name"]
      if "server.jdbc.user.name" in self.ambari_props:
        self.db_user = self.ambari_props["server.jdbc.user.name"]
      if "server.jdbc.user.passwd" in self.ambari_props:
        self.db_password = self.read_file(self.ambari_props["server.jdbc.user.passwd"])
      if "server.jdbc.hostname" in self.ambari_props:
        self.db_host = self.ambari_props["server.jdbc.hostname"]
      if "server.jdbc.url" in self.ambari_props:
        self.db_url = self.ambari_props["server.jdbc.url"]
      if "ambari-server.user" in self.ambari_props:
        self.ambari_server_user = self.ambari_props["ambari-server.user"]

      #Logger.info("Using database type: {0}, name: {1}, host: {2}".format(self.db_type, self.db_name, self.db_host))
      connection_string = "dbname='{0}' user='{1}' host='{2}' password='{3}'".format(self.db_name, self.db_user, self.db_host, self.db_password)

      if self.db_type == DB_TYPE.POSTGRES:
        try:
          import psycopg2     # covered by GNU Lesser General Public License
        except Exception, e:
          Logger.error("Need to install python-psycopg2 package for Postgres DB. E.g., yum install python-psycopg2\n")
          self.terminate()
      elif self.db_type == DB_TYPE.MYSQL:
        try:
          import pymysql      # covered by MIT License
        except Exception, e:
          Logger.error("Need to install PyMySQL package for Python. E.g., yum install python-setuptools && easy_install pip && pip install PyMySQL\n")
          self.terminate()
      else:
        Logger.error("Unknown database type: {0}.".format(self.db_type))
        self.terminate()

      self.conn = None
      self.cursor = None
      try:
        Logger.debug("Initializing database connection and cursor.")
        if self.db_type == DB_TYPE.POSTGRES:
          self.conn = psycopg2.connect(connection_string)
          self.cursor = self.conn.cursor()
        elif self.db_type == DB_TYPE.MYSQL:
          self.conn = pymysql.connect(self.db_host, self.db_user, self.db_password, self.db_name)
          self.cursor = self.conn.cursor()

        Logger.debug("Created database connection and cursor.")
        self.cursor.execute("SELECT metainfo_key, metainfo_value FROM metainfo WHERE metainfo_key='version';")
        rows = self.cursor.fetchall()
        if rows and len(rows) == 1:
          self.ambari_version = rows[0][1]
    #      Logger.info("Connected to database!!! Ambari version is {0}\n".format(self.ambari_version))

          # Must be Ambari 2.0.0 or higher
          if self.compare_versions(self.ambari_version, MIN_AMBARI_VERSION) < 0:
            Logger.error("Must be running Ambari Version {0} or higher.\n".format(MIN_AMBARI_VERSION))
            self.terminate()
        else:
          Logger.error("Unable to determine Ambari version.")
          self.terminate()

        self.set_cluster()
      except Exception, e:
        Logger.error("I am unable to connect to the database. Error: {0}\n".format(e))
        self.terminate()
    else:
      raise Exception("Could not find file {0}".format(AMBARI_PROPERTIES_LOCATION))

  def read_conf_file(self, file_path):
    """
    Parse the configuration file, and return a dictionary of key, value pairs.
    Ignore any lines that begin with #
    :param file_path: Properties file to parse.
    :return: Dictionary with key, value pairs.
    """
    ambari_props = {}
    if os.path.exists(file_path):
      with open(file_path, "r") as f:
        lines = f.readlines()
        if lines:
          Logger.debug("Reading file {0}, has {1} lines.".format(file_path, len(lines)))
          for l in lines:
            l = l.strip()
            if l.startswith("#"):
              continue
            parts = l.split("=")
            if len(parts) >= 2:
              prop = parts[0]
              value = "".join(parts[1:])
              ambari_props[prop] = value
    return ambari_props

  def read_file(self, file_path):
    """
    :param file_path: File to read. Typically the ambari database password file.
    :return: Return the contents of the file
    """
    if os.path.exists(file_path):
      with open(file_path, "r") as f:
        lines = f.readlines()
        return "\n".join(lines)
    return None

  def compare_versions(self, version1, version2):
    """
    Used to compare  Ambari Versions.
    E.g., Ambari version 2.0.1 vs 2.1.1,
    :param version1: First parameter for version
    :param version2: Second parameter for version
    :return: Returns -1 if version1 is before version2, 0 if they are equal, and 1 if version1 is after version2
    """
    max_segments = max(len(version1.split(".")), len(version2.split(".")))
    return cmp(self.__normalize_version(version1, desired_segments=max_segments), self.__normalize_version(version2, desired_segments=max_segments))

  def __normalize_version(self, v, desired_segments=0):
    """
    :param v: Input string of the form "#.#.#" or "#.#.#.#"
    :param desired_segments: If greater than 0, and if v has fewer segments this parameter, will pad v with segments
    containing "0" until the desired segments is reached.
    :return: Returns a list of integers representing the segments of the version
    """
    v_list = v.split(".")
    if desired_segments > 0 and len(v_list) < desired_segments:
      v_list = v_list + ((desired_segments - len(v_list)) * ["0", ])
    return [int(x) for x in v_list]

  def set_cluster(self):
    self.cluster_id = None
    self.cluster_name = None
    try:
      query = "SELECT cluster_id, cluster_name FROM clusters ORDER BY cluster_name;"
      self.cursor.execute(query)
      rows = self.cursor.fetchall()
      if rows:
        if len(rows) == 1:
          if len(rows[0]) == 2:
            self.cluster_id = int(rows[0][0])
            self.cluster_name = rows[0][1]
        pass

        if self.cluster_name is None:
          Logger.error("Unable to determine the cluster name.\n")
          self.terminate()
      else:
        Logger.error("Unable to get cluster from query: {0}\n".format(query))
        self.terminate()
    except Exception, e:
      Logger.error("Caught an exception. Error: {0}\n".format(e.message))
      self.terminate()

  def pre_upgrade_checks(self):
    """
    Ambari version
    Operating System
    JDK Version
    JCE Version
    Physical Memory
    Number of Nodes
    :return:
    """

    #HostOverview
    Logger.info("******************************************************************************************************************************************************")
    Logger.info("\t\t\t\t\t\t\tHOST OVERVIEW")
    Logger.info("******************************************************************************************************************************************************")
    print ("\n")
    Logger.info("Ambari version\t\t:{0}".format(self.ambari_version))

    #Check OS
    os = platform.dist()
    if os[1] != None:
      Logger.info("Operating System\t\t:{0} {1} - {2}".format(os[0],os[1],os[2]))
    else:
      Logger.error("Unable to fetch OS details.")
      self.terminate()
      return

    self.check_java_version()
    self.check_exactly_one_current_version()


    #Check if rack awareness is enabled ?
    rack_awareness = "SELECT DISTINCT rack_info FROM hosts WHERE rack_info!='/default-rack';"
    self.cursor.execute(rack_awareness)
    result = self.cursor.fetchone()
    if result is None or len(result) != 1:
      Logger.info("Rack Awareness ?\t\tNo\n")
    else:
      Logger.info("Rack Awareness ?\t\tYes\n")

    #Security Overview
    self.check_security()

    #Check High Availability configuration
    self.check_high_availability()

    #Check Metastores
    self.check_metastore()

  def check_security(self):
    Logger.info("******************************************************************************************************************************************************")
    Logger.info("\t\t\t\t\t\t\tSECURITY OVERVIEW")
    Logger.info("******************************************************************************************************************************************************")
    print ("\n")
    #Check if Kerberos is enabled
    query = "select security_state from servicedesiredstate where security_state!='UNSECURED' and service_name='KERBEROS';"
    Logger.debug("Running query: {0}".format(query))
    self.cursor.execute(query)
    row = self.cursor.fetchone()
    if row and len(row) > 0 and row[0] == "SECURED_KERBEROS":
      Logger.info("Kerberos: Enabled\t:Yes")
      # Check Kerberos: Ambari Managed
      query = "select t.type_name,t.config_data,t.version from clusterconfig t JOIN (select max(version) as version,type_name from clusterconfig group by type_name) m ON t.type_name=m.type_name and t.version=m.version where t.type_name like 'kerberos%' and config_data like '%manage_identities%true%';"
      Logger.debug("Running query: {0}".format(query))
      self.cursor.execute(query)
      row = self.cursor.fetchone()
      if row and len(row) > 0:
          Logger.info("Kerberos: Ambari Managed\t:Yes")
      else:
          Logger.info("Kerberos: Ambari Managed\t: No")
    else:
      Logger.info("Kerberos: Enabled\t\t\t: No")

    #Check if Ranger is installed
    query = "SELECT sd.service_name,sd.desired_state FROM servicedesiredstate sd JOIN clusters c ON sd.cluster_id = c.cluster_id WHERE sd.service_name='RANGER';"
    Logger.debug("Running query: {0}".format(query))
    self.cursor.execute(query)
    row = self.cursor.fetchone()
    if row and len(row) > 0:
      Logger.info("Ranger\t:{0}".format(row[1]))
      #Check Ranger Plugin's
      query1= "select t.type_name,t.config_data,t.version from clusterconfig t JOIN (select max(version) as version,type_name from clusterconfig group by type_name) m ON t.type_name=m.type_name and t.version=m.version where t.type_name like 'ranger-%-plugin-properties';"
      Logger.debug("Running query: {0}".format(query1))
      self.cursor.execute(query1)
      row1 = self.cursor.fetchall()
      if row1 and len(row1) > 0:
        for row in range(len(row1)):
            plugin = "ranger-"+ row1[row][0].split('-')[1] +"-plugin-enabled"
            data = json.loads(row1[row][1])
            Logger.info("Ranger Plugin\t:{0} - {1}".format(plugin,data[plugin]))
      print ("\n")
    else:
      Logger.info("Ranger\t: No\n")


    #Check Metastore DB's
  def check_metastore(self):
    Logger.info("******************************************************************************************************************************************************")
    Logger.info("\t\t\t\t\t\t\tMETASTORE DB VERSIONS")
    Logger.info("******************************************************************************************************************************************************")
    print ("\n")
    #Check Ambari metastore
    Logger.info("Ambari Metastore\t:{0}".format(self.ambari_props["server.jdbc.database"]))

    #Check Hive Metastore
    query = "select t.config_data from clusterconfig t JOIN (select max(version) as version,type_name from clusterconfig group by type_name) m ON t.type_name=m.type_name and t.version=m.version where t.type_name like 'hive_env';"
    Logger.debug("Running query: {0}".format(query))
    self.cursor.execute(query)
    row = self.cursor.fetchone()
    if row and len(row) > 0:
      data = json.loads(row[0])
      Logger.info("Hive Metastore\t:{0}".format(data["hive_database_type"]))
    else:
      Logger.info("Hive Metastore\t:NA")

    # Check Ranger Metastore
    query = "select t.config_data from clusterconfig t JOIN (select max(version) as version,type_name from clusterconfig group by type_name) m ON t.type_name=m.type_name and t.version=m.version where t.type_name like 'ranger-admin-site';"
    Logger.debug("Running query: {0}".format(query))
    self.cursor.execute(query)
    row = self.cursor.fetchone()
    if row and len(row) > 0:
      data = json.loads(row[0])
      Logger.info("Ranger Metastore\t:{0}".format(data["ranger.jpa.jdbc.driver"]))
    else:
      Logger.info("Ranger Metastore\t:NA")

  # Check Oozie Metastore
    query = "select t.config_data from clusterconfig t JOIN (select max(version) as version,type_name from clusterconfig group by type_name) m ON t.type_name=m.type_name and t.version=m.version where t.type_name like 'oozie-env';"
    Logger.debug("Running query: {0}".format(query))
    self.cursor.execute(query)
    row = self.cursor.fetchone()
    if row and len(row) > 0:
      data = json.loads(row[0])
      Logger.info("Oozie Metastore\t:{0}".format(data["oozie_database"]))
    else:
      Logger.info("Oozie Metastore\t:NA")

  def check_high_availability(self):
    Logger.info("******************************************************************************************************************************************************")
    Logger.info("\t\t\t\t\t\t\tHIGH AVAILABILITY CONFIGURATIONS")
    Logger.info("******************************************************************************************************************************************************")
    print ("\n")
    #Check if Namenode is HA enabled
    query = "select t.config_data from clusterconfig t JOIN (select max(version) as version,type_name from clusterconfig group by type_name) m ON t.type_name=m.type_name and t.version=m.version where t.type_name like 'hdfs-site' and config_data like '%dfs.nameservices%';"
    Logger.debug("Running query: {0}".format(query))
    self.cursor.execute(query)
    row = self.cursor.fetchone()
    if row and len(row) > 0:
      Logger.info("HDFS\t:Yes")
    else:
      Logger.info("HDFS\t:No")

  # Check if Resource Manager is HA enabled
    query = "select t.type_name,t.config_data,t.version from clusterconfig t JOIN (select max(version) as version,type_name from clusterconfig group by type_name) m ON t.type_name=m.type_name and t.version=m.version where t.type_name like 'yarn-site' and config_data like '%\"yarn.resourcemanager.ha.enabled\":\"true\"%';"
    Logger.debug("Running query: {0}".format(query))
    self.cursor.execute(query)
    row = self.cursor.fetchone()
    if row and len(row) > 0:
      Logger.info("YARN\t:Yes")
    else:
      Logger.info("YARN\t:No")

  # Check if Hive metastore is HA enabled
    query = "select t.config_data from clusterconfig t JOIN (select max(version) as version,type_name from clusterconfig group by type_name) m ON t.type_name=m.type_name and t.version=m.version where t.type_name like 'hive-site' and config_data like '%hive.metastore.uris%';"
    Logger.debug("Running query: {0}".format(query))
    self.cursor.execute(query)
    row = self.cursor.fetchone()
    if row and len(row) > 0:
      data = json.loads(row[0])
      hiveha = len(data["hive.metastore.uris"].split(','))
      if hiveha > 1:
        Logger.info("Hive Metastore\t:Yes")
      else:
        Logger.info("Hive Metastore\t:No")

      # Check if Hiveserver 2 is HA enabled
      query = "select count(hc.component_name) from hostcomponentstate hc JOIN clusters c ON hc.cluster_id = c.cluster_id where hc.component_name='HIVE_SERVER';"
      Logger.debug("Running query: {0}".format(query))
      self.cursor.execute(query)
      row = self.cursor.fetchone()
      if row and len(row) > 0:
          if row[0] > 1:
              Logger.info("Hiveserver 2\t:Yes")
          else:
              Logger.info("Hiveserver 2\t:No")
      else:
          Logger.info("Hiveserver 2\t:NA")

      # Check if WebHcat is HA enabled
      query = "select count(hc.component_name) from hostcomponentstate hc JOIN clusters c ON hc.cluster_id = c.cluster_id where hc.component_name='WEBHCAT_SERVER';"
      Logger.debug("Running query: {0}".format(query))
      self.cursor.execute(query)
      row = self.cursor.fetchone()
      if row and len(row) > 0:
          if row[0] > 1:
              Logger.info("WebHcat\t:Yes")
          else:
              Logger.info("WebHcat\t:No")
      else:
          Logger.info("WebHcat\t:NA")


    # Check if Oozie is HA enabled
    query = "select count(hc.component_name) from hostcomponentstate hc JOIN clusters c ON hc.cluster_id = c.cluster_id where hc.component_name='OOZIE_SERVER';"
    Logger.debug("Running query: {0}".format(query))
    self.cursor.execute(query)
    row = self.cursor.fetchone()
    if row and len(row) > 0:
      if row[0] >1:
        Logger.info("Oozie\t:Yes")
      else:
        Logger.info("Oozie\t:No")
    else:
        Logger.info("Oozie\t:NA")

     # Check if Hbase is HA enabled
    query = "select count(hc.component_name) from hostcomponentstate hc JOIN clusters c ON hc.cluster_id = c.cluster_id where hc.component_name='HBASE_MASTER';"
    Logger.debug("Running query: {0}".format(query))
    self.cursor.execute(query)
    row = self.cursor.fetchone()
    if row and len(row) > 0:
        if row[0] > 1:
            Logger.info("Hbase\t:Yes")
        else:
            Logger.info("Hbase\t:No")
    else:
        Logger.info("Hbase\t:NA")

    print ("\n")


  def check_exactly_one_current_version(self):
    """
    If there are no cluster_version records, or host_version records, the user will have to restart at least one component
    that can advertise a version. Ideally, they need to restart all services.
    If there is exactly one cluster_version, and every host_version record corresponds to the same repo_version,
    then need to ensure that all of these entities have a state of CURRENT.
    If not, prompt user if they want to change all to CURRENT.
    """
    expected_state = "CURRENT"

    query = "SELECT COUNT(*) FROM cluster_version;"
    self.cursor.execute(query)
    result = self.cursor.fetchone()
    if result is None or len(result) != 1:
      Logger.error("Unable to run query: {0}".format(query))
      return

    count = result[0]
    if count == 0:
      msg = "There are no cluster_versions. Start ambari-server, and then perform a Restart on one of the services.\n" + \
        "Then navigate to the \"Stacks and Versions > Versions\" page and ensure you can see the stack version.\n" + \
        "Next, restart all services, one-by-one, so that Ambari knows what version each component is running."
      Logger.warning(msg)
    elif count == 1:
      query = "SELECT rv.repo_version_id, rv.version, cv.state FROM cluster_version cv JOIN repo_version rv ON cv.repo_version_id = rv.repo_version_id;"
      self.cursor.execute(query)
      result = self.cursor.fetchone()

      repo_version_id = None
      repo_version = None
      cluster_version_state = None

      if result and len(result) == 3:
        repo_version_id = result[0]
        repo_version = result[1]
        cluster_version_state = result[2]

      if repo_version_id and repo_version and cluster_version_state:
        if cluster_version_state.upper() == expected_state:
          self.check_all_hosts(repo_version_id, repo_version)
          Logger.info("******************************************************************************************************************************************************")
          Logger.info("\t\t\t\t\t\t\tHDP STACK OVERVIEW")
	  Logger.info("******************************************************************************************************************************************************")
          print ("\n")
          Logger.info("Cluster HDP Version\t{0}".format(repo_version))
          Logger.info("Cluster State\t{0}".format(cluster_version_state))
          Logger.info("Ambari version\t:{0}".format(self.ambari_version))

          if self.ambari_server_user != "root" :
            Logger.info("Ambari Server as non-root?\tYes")
          else :
            Logger.info("Ambari Server as non-root?\tNo")

          # Read ambari-agent.ini file
          if os.path.exists(AMBARI_AGENT_INI):
            self.ambari_agent_props = self.read_conf_file(AMBARI_AGENT_INI)
            Logger.debug("Reading file {0}.".format(self.ambari_agent_props))
            if "run_as_user" in self.ambari_agent_props:
              self.run_as_user = self.ambari_agent_props["run_as_user"]
            if self.run_as_user != "root":
              Logger.info("Ambari Agent as non-root?\tYes")
            else:
              Logger.info("Ambari Agent as non-root?\tNo")
          else:
            Logger.error("Unable to read ambari-agent.ini file")

        else:
          Logger.error("Cluster Version {0} should have a state of {1} but is {2}. Make sure to restart all of the Services.".format(repo_version, expected_state, cluster_version_state))
      else:
        Logger.error("Unable to run query: {0}".format(query))
    elif count > 1:
      # Ensure at least one Cluster Version is CURRENT
      Logger.info("Found multiple Cluster versions, checking that exactly one is {0}.".format(expected_state))
      query = "SELECT rv.repo_version_id, rv.version, cv.state FROM cluster_version cv JOIN repo_version rv ON cv.repo_version_id = rv.repo_version_id WHERE cv.state = '{0}';".format(expected_state)
      self.cursor.execute(query)
      rows = self.cursor.fetchall()
      if rows:
        if len(rows) == 1:
          Logger.info("Good news; Cluster Version {0} has a state of {1}.".format(rows[0][1], expected_state))
          self.check_all_hosts_current(rows[0][0], rows[0][1])
        elif len(rows) > 1:
          # Take the repo_version's version column
          repo_versions = [row[1] for row in rows if len(row) == 3]
          Logger.error("Found multiple cluster versions with a state of {0}, but only one should be {0}.\n" \
                       "Will need to fix this manually, please contact Support. Cluster Versions found: {1}".format(expected_state, ", ".join(repo_versions)))
      else:
        Logger.error("Unable to run query: {0}\n".format(query))
    pass

  def check_all_hosts (self, repo_version_id, version_name):
    """
    Ensure that all of the hosts in the cluster have a state of CURRENT for the host_version that corresponds to the id.
    :param repo_version_id: repo_version table's repo_version_id column
    :param version_name: repo_version table's version column
    """
    if self.compare_versions(self.ambari_version, "2.1.0") < 0:
      query1 = "SELECT chm.host_name from ClusterHostMapping chm JOIN clusters c ON c.cluster_name = '{0}';".format(self.cluster_name)
    else:
      query1 = "SELECT h.host_name from ClusterHostMapping chm JOIN clusters c ON c.cluster_name = '{0}' JOIN hosts h ON chm.host_id = h.host_id;".format(self.cluster_name)

    if self.compare_versions(self.ambari_version, "2.1.0") < 0:
      query2 = "SELECT hv.host_name, hv.state FROM host_version hv WHERE hv.repo_version_id = {0};".format(repo_version_id)
    else:
      #query2 = "SELECT hv.state,h.host_name FROM hosts h JOIN host_version hv ON h.host_id = hv.host_id WHERE hv.repo_version_id = {0};".format(repo_version_id)
      query2 = "SELECT hv.state,h.host_name, hs.health_status,hs.agent_version,(h.total_mem/1024/1024) as total_mem_gb,(hs.available_mem/1024/1024) as available_mem_gb FROM hosts h JOIN host_version hv ON h.host_id = hv.host_id JOIN hoststate hs ON h.host_id = hs.host_id WHERE hv.repo_version_id = {0} order by h.host_name;".format(repo_version_id)
    # All cluster hosts
    host_names = set()
    self.cursor.execute(query1)
    rows = self.cursor.fetchall()
    if self.options.verbose:
      Logger.debug(query1 + "\n")
    if rows and len(rows) > 0:
      host_names = set([row[0] for row in rows if len(row) == 1])
      Logger.debug("Hosts: {0}".format(", ".join(host_names)))

    host_name_to_state = {} # keys should be a subset of host_names
    hosts_with_repo_version_state_not_in_current = set()
    self.cursor.execute(query2 + "\n")
    rows = self.cursor.fetchall()
    Logger.info("******************************************************************************************************************************************************")
    Logger.info("\t\t\t\t\t\t\tHOST(S) STATE\t")
    Logger.info("******************************************************************************************************************************************************\n")
    Logger.info("------------------------------------------------------------------------------------------------------------------------------------------------------")
    Logger.info("State\t\tHostname\t\t\t\tHealth\t\tAgentVersion\tTotalMemory\tAvailableMemory")
    Logger.info("------------------------------------------------------------------------------------------------------------------------------------------------------")

    if rows and len(rows) > 0:
        for row in range(len(rows)):
            data = json.loads(rows[row][2])
            data1 = json.loads(rows[row][3])
            Logger.info("{0}\t\t{1}\t\t{2}\t\t{3}\t\t{4}\t\t{5}".format(rows[row][0], rows[row][1], data["healthStatus"], data1["version"], rows[row][4], rows[row][5]))
    print ("\n")
    Logger.debug(query2)
    if rows and len(rows) > 0:
      for row in rows:
        if len(row) == 6:
          host_name = row[1]
          state = row[0]
          host_name_to_state[host_name] = state
          if state.upper() != "CURRENT":
            hosts_with_repo_version_state_not_in_current.add(host_name)
    host_names_with_version = set(host_name_to_state.keys())
    host_names_without_version = host_names - host_names_with_version
   # Logger.info("\t\tHost(s) state Summary")
    if len(host_names) > 0:
      if len(host_names_without_version) > 0:
        Logger.error("{0} host(s) do not have a Host Version for Repo Version {1}.\n" \
                     "Host(s):\n{2}\n".
                     format(len(host_names_without_version), version_name, ", ".join(host_names_without_version)))

      if len(hosts_with_repo_version_state_not_in_current) > 0:
        Logger.error("{0} host(s) have a Host Version for Repo Version {1} but the state is not CURRENT.\n" \
                     "Host(s):\n{2}\n".
                     format(len(hosts_with_repo_version_state_not_in_current), version_name, ", ".join(hosts_with_repo_version_state_not_in_current)))

      if len(host_names_without_version) == 0 and len(hosts_with_repo_version_state_not_in_current) == 0:
        Logger.info("Found {0} host(s) in the cluster, and all have a Host Version of CURRENT for " \
                    "Repo Version {1}. Things look good.\n".format(len(host_names), version_name))
      else:
        Logger.error("Make sure that all of these hosts are heartbeating, that they have the packages installed, the\n" \
          "hdp-select symlinks are correct, and that the services on these hosts have been restarated.\n")
    pass

if __name__ == '__main__':
  magician = PUChecker(sys.argv)

