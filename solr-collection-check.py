#!/usr/bin/python2.7
import socket, os
import traceback
import json

from resource_management.core.exceptions import ComponentIsNotRunning
from resource_management.libraries.functions import get_kinit_path
from resource_management.core.resources import Execute
from resource_management.core.environment import Environment



SECURITY_ENABLED_KEY = '{{cluster-env/security_enabled}}'

# Solr setting keys in Ambari
SOLR_PORT_KEY = 'check.solr.port'
SOLR_PORT_DEFAULT = '8886'
SOLR_CONNECTION_TIMEOUT_KEY = 'check.connection.timeout'
SOLR_CONNECTION_TIMEOUT_DEFAULT = 5
UI_SSL_ENABLED_KEY = 'check.ssl_config_option'
UI_SSL_ENABLED_KEY_DEFAULT = '{{infra-solr-env/infra_solr_ssl_enabled}}'

# Kerberos keys
KRB_EXEC_SEARCH_PATHS_KEY = '{{kerberos-env/executable_search_paths}}'
SMOKEUSER_KEYTAB_KEY = '{{cluster-env/smokeuser_keytab}}'
SMOKEUSER_PRINCIPAL_KEY = '{{cluster-env/smokeuser_principal_name}}'
SMOKEUSER_KEY = '{{cluster-env/smokeuser}}'

RESULT_CODE_OK = 'OK'
RESULT_CODE_CRITICAL = 'CRITICAL'
RESULT_CODE_UNKNOWN = 'UNKNOWN'


def get_tokens():
    return (SECURITY_ENABLED_KEY, SMOKEUSER_KEYTAB_KEY, SMOKEUSER_PRINCIPAL_KEY,
            SMOKEUSER_KEY, UI_SSL_ENABLED_KEY, KRB_EXEC_SEARCH_PATHS_KEY,
            SOLR_PORT_KEY)

def security_auth(configs, host_name, solr_user):
    """
  Call kinit before pursuit with any other action
  :type configs dict
  :type host_name str
  :type solr_user str
  """
    solr_kerberos_keytab = configs[
        SMOKEUSER_KEYTAB_KEY] if SMOKEUSER_KEYTAB_KEY in configs else None
    solr_principal = configs[SMOKEUSER_PRINCIPAL_KEY].replace(
        '_HOST', host_name.lower()) if SMOKEUSER_PRINCIPAL_KEY in configs else None
    krb_executable_search_paths = configs[
        KRB_EXEC_SEARCH_PATHS_KEY] if KRB_EXEC_SEARCH_PATHS_KEY in configs else None
    kinit_path_local = get_kinit_path(krb_executable_search_paths)

    if not solr_principal or not solr_kerberos_keytab:
        raise ComponentIsNotRunning(
            "Error: solr principal or solr kerberos keytab can't be None")

    kinit_cmd = "{kinit_path_local} -kt {solr_kerberos_keytab} {solr_principal};".format(
        kinit_path_local=kinit_path_local,
        solr_kerberos_keytab=solr_kerberos_keytab,
        solr_principal=solr_principal)

    Execute(kinit_cmd, user=solr_user)


def execute(configs={}, parameters={}, host_name=None):

    if configs is None:
        return 'UNKNOWN', [
            'There were no configurations supplied to the script.'
        ]

    if host_name is None:
        host_name = socket.getfqdn()

    env = Environment.get_instance()

    solr_user = configs[SMOKEUSER_KEY]

    ui_ssl_enabled = False
    ui_ssl_enabled_key = UI_SSL_ENABLED_KEY_DEFAULT

    security_enabled = False
    if SECURITY_ENABLED_KEY in configs:
        security_enabled = str(configs[SECURITY_ENABLED_KEY]).upper() == 'TRUE'

    # check parameters
    if UI_SSL_ENABLED_KEY in parameters:
        ui_ssl_enabled_key = parameters[UI_SSL_ENABLED_KEY]

    if ui_ssl_enabled_key in configs:
        ui_ssl_enabled = str(configs[UI_SSL_ENABLED_KEY]).upper() == 'TRUE'

    solr_port = SOLR_PORT_DEFAULT
    if SOLR_PORT_KEY in parameters:
        solr_port = parameters[SOLR_PORT_KEY]

    connection_timeout = SOLR_CONNECTION_TIMEOUT_DEFAULT
    if SOLR_CONNECTION_TIMEOUT_KEY in parameters:
        connection_timeout = parameters[SOLR_CONNECTION_TIMEOUT_KEY]

    if security_enabled:
        try:
            security_auth(configs, host_name, solr_user)
        except Exception as e:
            return RESULT_CODE_CRITICAL, ["kinit error: " + str(e)]

    if ui_ssl_enabled:
        scheme = "https"
    else:
        scheme = "http"

    state_file = "{}/solrstatus.json".format(env.tmp_dir)
    cmd = "curl -s -m {} -o {} --negotiate -u: -k '{}://{}:{}/solr/admin/collections?action=clusterstatus&wt=json'".format(
        connection_timeout, state_file,scheme,host_name,solr_port)
    try:
       Execute(cmd, tries=2, try_sleep=3, user=solr_user, logoutput=True) 
    except:
      return (RESULT_CODE_CRITICAL, ["curl cannot reach Solr, solr seems to be down"])
    try:
        state = json.load(open(state_file))
    except:
       return (RESULT_CODE_CRITICAL, ["Get status failed, could not load state file"])

    os.remove(state_file)
    cluster_state = state['cluster']['collections']
    outdata = dict()
    outdata['shards'] = list()
    outdata['replicas'] = list()

    for key in cluster_state:
        for shard, shard_data in cluster_state[key]['shards'].iteritems():
           for replica, replica_data in shard_data['replicas'].iteritems():
              if replica_data['state'] != 'active':
                  rname = '-'.join([key, shard, replica])
                  outdata['replicas'].append({rname: replica_data['state']})
              else:
                  pass

           if shard_data['state'] != 'active':
               sname = '-'.join([key, shard])
               outdata['shards'].append({sname: shard_data['state']})
           else:
               pass

    if outdata['shards'] or outdata['replicas']:
        return (RESULT_CODE_CRITICAL, ["Replicas or Shards found not active. %s" % json.dumps(outdata)])
    else:
        return (RESULT_CODE_OK, ["All Shards and replicas healthy"])
