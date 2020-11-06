import sys

#from openstackclient.shell import OpenStackShell
#from cliff import app

import subprocess
import json 

def run(create_forw,auth_param,params):

   create_forw.extend(auth_param)
   create_forw.extend(params)

   process = subprocess.Popen(create_forw,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
   process.wait()
   stdout, stderr = process.communicate()

   try:
      result=json.loads(stdout.decode("utf-8"))
   except:
      result=[]

   return result

#def run(create_forw,auth_param,params):
#    create_forw.extend(auth_param)
#    create_forw.extend(params)
#    cmd=OpenStackShell()
#    X=cmd.run(create_forw)
#    del cmd
#    return X

def floating_ip_port_forwarding_create(param):
    create_forw=['/usr/bin/openstack', 'floating', 'ip', 'port', 'forwarding', 'create']
    auth_param=['--os-auth-url', param['endpoint'], '--os-token', param['token_id'], '--os-user-id', param['user_id'], '--os-project-id', param['project_id'],
                '--os-project-domain-name', param['user_domain_name'], '--os-auth-type', 'token' ]
    params=[param['pool'], '--protocol', param['protocol'], '--external-protocol-port', param['source_port'],
            '--internal-protocol-port', param['dst_port'], '--port', param['port'], '--internal-ip-address', param['portip'], '-f', 'json' ]

    return run(create_forw,auth_param,params)


def floating_ip_port_forwarding_list(param):
    create_forw=['/usr/bin/openstack', 'floating', 'ip', 'port', 'forwarding', 'list']
    auth_param=['--os-auth-url', param['endpoint'], '--os-token', param['token_id'], '--os-user-id', param['user_id'], '--os-project-id', param['project_id'],
                '--os-project-domain-name', param['user_domain_name'], '--os-auth-type', 'token' ]
    params=[param['id'], '-f', 'json' ]

    return run(create_forw,auth_param,params)

def floating_ip_port_forwarding_delete(param):
    create_forw=['/usr/bin/openstack', 'floating', 'ip', 'port', 'forwarding', 'delete']
    auth_param=['--os-auth-url', param['endpoint'], '--os-token', param['token_id'], '--os-user-id', param['user_id'], '--os-project-id', param['project_id'],
                '--os-project-domain-name', param['user_domain_name'], '--os-auth-type', 'token' ]
    params=[param['id'], param['forward'] ]

    return run(create_forw,auth_param,params)
