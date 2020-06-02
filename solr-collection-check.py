#!/usr/bin/python2.7
import socket, os
import traceback
import json

from resource_management.core.exceptions import ComponentIsNotRunning
from resource_management.libraries.functions import get_kinit_path
from resource_management.core.resources import Execute
from resource_management.core.environment import Environment



SECURITY_ENABLED_KEY = '{{cluster-env/security_enabled}}'
SOLR_PORT_KEY = '{{infra-solr-env/infra_solr_port}}'
SOLR_KEYTAB_KEY = '{{infra-solr-env/infra_solr_kerberos_keytab}}'
SOLR_PRINCIPAL_KEY = '{{infra-solr-env/infra_solr_kerberos_principal}}'
SOLR_USER_KEY = '{{infra-solr-env/infra_solr_user}}'

UI_SSL_ENABLED = '{{infra-solr-env/infra_solr_ssl_enabled}}'

KRB_EXEC_SEARCH_PATHS_KEY = '{{kerberos-env/executable_search_paths}}'

RESULT_CODE_OK = 'OK'
RESULT_CODE_CRITICAL = 'CRITICAL'
RESULT_CODE_UNKNOWN = 'UNKNOWN'


def get_tokens():
    return (SECURITY_ENABLED_KEY, SOLR_USER_KEY, SOLR_KEYTAB_KEY, SOLR_PRINCIPAL_KEY,
            SOLR_USER_KEY, UI_SSL_ENABLED, KRB_EXEC_SEARCH_PATHS_KEY,
            SOLR_PORT_KEY)

def security_auth(configs, host_name, infra_solr_user):
    """
  Call kinit before pursuit with any other action
  :type configs dict
  :type host_name str
  :type solr_user str
  """
    solr_kerberos_keytab = configs[
        SOLR_KEYTAB_KEY] if SOLR_KEYTAB_KEY in configs else None
    solr_principal = configs[SOLR_PRINCIPAL_KEY].replace(
        '_HOST', host_name.lower()) if SOLR_PRINCIPAL_KEY in configs else None
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

    Execute(kinit_cmd, user=infra_solr_user)


def execute(configs={}, parameters={}, host_name=None):

    if configs is None:
        return 'UNKNOWN', [
            'There were no configurations supplied to the script.'
        ]

    if host_name is None:
        host_name = socket.getfqdn()

    env = Environment.get_instance()

    infra_solr_user = configs[SOLR_USER_KEY]

    ui_ssl_enabled = False
    if UI_SSL_ENABLED in configs:
        ui_ssl_enabled = str(configs[UI_SSL_ENABLED]).upper() == 'TRUE'

    solr_port = configs[SOLR_PORT_KEY]

    security_enabled = False
    if SECURITY_ENABLED_KEY in configs:
        security_enabled = str(configs[SECURITY_ENABLED_KEY]).upper() == 'TRUE'

    if security_enabled:
        try:
            security_auth(configs, host_name, infra_solr_user)
        except Exception as e:
            return RESULT_CODE_CRITICAL, ["kinit error: " + str(e)]

    curl_auth = None
    if ui_ssl_enabled:
        scheme = "https"
        curl_auth = "--cert /etc/security/certificates/host.crt --key /etc/security/certificates/host.key"
    else:
        scheme = "http"

    state_file = "{}/solrstatus.json".format(env.tmp_dir)
    cmd = "curl -s -o {} --negotiate -u: -k '{}://{}:{}/solr/admin/collections?action=clusterstatus&wt=json'".format(state_file,scheme,host_name,solr_port)
    try:
       Execute(cmd, tries=2, try_sleep=3, user=infra_solr_user, logoutput=True) 
    except:
      return (RESULT_CODE_CRITICAL, ["curl cannot reach Solr, solr seems to be down"])
    try:
        state = json.load(open(state_file))
    except:
       return (RESULT_CODE_CRITICAL, ["The curl command failed, could not load state file"])

    os.remove(state_file)
    cluster_state = state['cluster']['collections']
    #replica_status_critical = dict()
    #shard_status_critical = dict()
    outdata = dict()
    outdata['shards'] = list()
    outdata['replicas'] = list()

    for key in cluster_state:
        for shard, shard_data in cluster_state[key]['shards'].iteritems():
           for replica, replica_data in shard_data['replicas'].iteritems():
              if replica_data['state'] != 'active':
                  rname = '-'.join([key, shard, replica])
                  #replica_status_critical[rname] = replica_data['state']
                  outdata['replicas'].append({rname: replica_data['state']})
              else:
                  #return (RESULT_CODE_CRITICAL, ["replica: %s" % replica + " " +"of shard: %s" % shard + " " +"is DOWN"])
                  pass

           if shard_data['state'] != 'active':
               sname = '-'.join([key, shard])
               #shard_status_critical[sname] = shard_data['state']
               outdata['shards'].append({sname: shard_data['state']})
           else:
               #return (RESULT_CODE_CRITICAL, ["shard: %s" % shard + " " +"of collection: %s" % key + " " +"is DOWN"])
               pass

    if outdata['shards'] or outdata['replicas']:
        return (RESULT_CODE_CRITICAL, ["Replicas or Shards found not active. %s" % json.dumps(outdata)])
    else:
        return (RESULT_CODE_OK, ["All Shards and replicas healthy"])
