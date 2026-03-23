from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
'''

EXAMPLES = r'''
'''

RETURN = r'''
'''

import shutil
import glob
import os
import re


def get_fingerprint(module, path):
    fingerprint_pattern = r'Fingerprint:\s*(.*)$'
    if os.path.isfile(path):
        cmd = [
            'icinga2',
            'pki',
            'verify',
            '--cert', path,
        ]
        rc, stdout, stderr = module.run_command(
            cmd,
            executable=None,
            use_unsafe_shell=False,
            encoding=None,
            data=None,
            binary_data=True,
            expand_user_and_vars=True,
        )
        match = re.search(fingerprint_pattern, str(stdout).strip('"'))
        if match:
            # Normalize fingerprint
            fingerprint = match.group(1).replace('\\n', '').replace(' ', '').lower()
            return fingerprint
        return None


def get_return_values(module, cn, ca_directory, certs_directory):
    ### Get CA and certificate fingerprints
    rv = dict(
        ca_fingerprint = None,
        cert_fingerprint = None,
    )
    rv['ca_fingerprint'] = get_fingerprint(module, os.path.join(ca_directory, 'ca.crt'))
    rv['cert_fingerprint'] = get_fingerprint(module, os.path.join(certs_directory, cn + '.crt'))
    return rv


def configure(module, cn, zones, sysconf_directory):
    ret = dict(
        changed = False,
    )

    ### Ensure const NodeName is set to given CN
    with open(os.path.join(sysconf_directory, 'constants.conf'), 'r') as constants:
        lines = constants.readlines()

    new_lines = list()
    pattern = '^const NodeName.*$'
    target = 'const NodeName = "{}"'.format(cn)

    for line in lines:
        if re.search(pattern, line):
            if line.rstrip('\n') != target:
                new_lines.append(target + '\n')
                ret['changed'] = True
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)


    if not any(re.search(pattern, line) for line in lines):
        new_lines.append(target + '\n')
        changed = True

    with open(os.path.join(sysconf_directory, 'constants.conf'), 'w') as constants:
        constants.writelines(new_lines)

    
    ### Define zones.conf
    zones_conf = list()

    for zone in zones:
        if zone['_global']:
            zones_conf.append('object Zone "{}" {{'.format(zone['name']))
            zones_conf.append('  global = true')
            zones_conf.append('}')
            zones_conf.append('')
        else:
            # Add endpoints
            for endpoint in zone['endpoints']:
                zones_conf.append('object Endpoint "{}" {{'.format(endpoint['cn']))
                if endpoint['host']:
                    zones_conf.append('  host = "{}"'.format(endpoint['host']))
                if endpoint['port']:
                    zones_conf.append('  port = "{}"'.format(endpoint['port']))
                zones_conf.append('}')
                zones_conf.append('')

            # Add zone
            zones_conf.append('object Zone "{}" {{'.format(zone['name']))
            zones_conf.append('  endpoints = [')
            for endpoint in zone['endpoints']:
                zones_conf.append('    "{}",'.format(endpoint['cn']))
            zones_conf.append('  ]')
            if zone['parent']:
                zones_conf.append('  parent = "{}"'.format(zone['parent']))
            zones_conf.append('}')
            zones_conf.append('')
    new_zones = '\n'.join(zones_conf)

    current_zones = ""
    if os.path.isfile(os.path.join(sysconf_directory, 'zones.conf')):
        with open(os.path.join(sysconf_directory, 'zones.conf'), 'r') as zones_file:
            current_zones = zones_file.read()

    if new_zones != current_zones:
        with open(os.path.join(sysconf_directory, 'zones.conf'), 'w') as zones_file:
            zones_file.write(new_zones)
            ret['changed'] = True

    return ret
    

def master_setup(module, cn, ca_directory, certs_directory):
    ret = dict(
        changed = False,
    )

    ### Generate CA
    cmd = [
        'icinga2',
        'pki',
        'new-ca',
    ]

    if not glob.glob(os.path.join(ca_directory, 'ca.key')):
        rc, stdout, stderr = module.run_command(
            cmd,
            executable=None,
            use_unsafe_shell=False,
            encoding=None,
            data=None,
            binary_data=True,
            expand_user_and_vars=True,
        )
        if 'information/base: Writing private key to \'{}\''.format(os.path.join(ca_directory, 'ca.key')) in str(stdout):
            ret['changed'] = True
        elif 'critical/cli: Please re-run this command as a privileged user' in str(stdout):
            ret['fail_msg'] = 'This module has to be run as a privileged user or as the \'nagios\' user.'
    elif not glob.glob(os.path.join(ca_directory, 'ca.crt')):
        module.warn(
            '{} is already present while {} is missing. Not generating a new CA.'.format(
                os.path.join(ca_directory, 'ca.key'),
                os.path.join(ca_directory, 'ca.crt')
            )
        )
    else:
        shutil.copy(
            os.path.join(ca_directory, 'ca.crt'),
            os.path.join(certs_directory, 'ca.crt')
        )

    return ret


def agent_setup(module, cn, host, port, ticket, fingerprint, ignore_fingerprint, certs_directory):
    ret = dict(
        changed = False,
    )

    ### Get parent certificate
    cmd = [
        'icinga2',
        'pki',
        'save-cert',
        '--host',
        host,
        '--port',
        str(port),
        '--trustedcert',
        os.path.join(certs_directory, 'trusted-parent.crt'),
    ]
    if not glob.glob(os.path.join(certs_directory, 'trusted-parent.crt')):
        rc, stdout, stderr= module.run_command(
            cmd,
            executable=None,
            use_unsafe_shell=False,
            encoding=None,
            data=None,
            binary_data=True,
            expand_user_and_vars=True,
        )
        ret['changed'] = True

    ### Talk to master
    # This one also makes the node receive the new certificate once it's signed

    # Potential answers
    # information/cli: Writing CA certificate to file '/var/lib/icinga2/certs/ca.crt'.
    # information/cli: Writing signed certificate to file '/var/lib/icinga2/certs/<node_name>.crt'.
    #   → RC X
    #   → First connection after certificate is signed
    #
    # Could not fetch valid response. Please check the master log.
    #   → RC X 
    #   → If parent is available but does not know the own node's endpoint
    #
    # The certificates for CN '<node_name>' and its root CA are valid and uptodate. Skipping automated renewal.
    #   → RC 1
    #   → Connected normally, after getting valid certificate

    cmd = [
        'icinga2',
        'pki',
        'request',
        '--host', host,
        '--port', str(port),
        '--trustedcert', os.path.join(certs_directory, 'trusted-parent.crt'),
        '--ca', os.path.join(certs_directory, 'ca.crt'),
        '--key', os.path.join(certs_directory, cn + '.key'),
        '--cert', os.path.join(certs_directory, cn + '.crt'),
    ]
    if ticket:
        cmd.extend(['--ticket', ticket])

    rc, stdout, stderr = module.run_command(
        cmd,
        executable=None,
        use_unsafe_shell=False,
        encoding=None,
        data=None,
        binary_data=True,
        expand_user_and_vars=True,
    )

    # Validate fingerprint
    present_fingerprint = get_fingerprint(module, os.path.join(certs_directory, 'ca.crt'))
    if not ignore_fingerprint and fingerprint != present_fingerprint:
        ret['fail_msg'] = 'Fingerprint \'{}\' on host did not match provided fingerprint \'{}\'.'.format(
            present_fingerprint,
            fingerprint,
        )

    return ret


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            mode=dict(default='agent', choices=['agent', 'master', 'config'], type='str'),
            cn=dict(required=True, type='str'),
            host=dict(default=None, type='str'),
            port=dict(default=5665, type='int'),
            ticket=dict(default=None, type='str', no_log=True),

            zones=dict(
                type='list',
                elements='dict',
                options=dict(
                    name=dict(required=True, type='str'),
                    _global=dict(default=False, type='bool', aliases=['global']),
                    parent=dict(default=None, type='str'),
                    endpoints=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            cn=dict(required=True, type='str', aliases=['name']),
                            host=dict(default=None, type='str'),
                            port=dict(default=None, type='int'),
                        )
                    ),
                ),
            ),


            # Use that to verify
            fingerprint=dict(type='str'),
            ignore_fingerprint=dict(default=False, type='bool'),
        )
    )

    sysconf_directory = '/etc/icinga2'
    data_directory    = '/var/lib/icinga2'
    ca_directory      = os.path.join(data_directory, 'ca')
    certs_directory   = os.path.join(data_directory, 'certs')

    mode  = module.params['mode']
    cn    = module.params['cn']
    zones = module.params['zones']

    if mode == 'agent':
        host               = module.params['host']
        port               = module.params['port']
        ticket             = module.params['ticket']
        fingerprint        = module.params['fingerprint']
        ignore_fingerprint = module.params['ignore_fingerprint']

    ret = dict(
        changed = False,
    )

    ### Create certs/ if not present
    if os.path.isdir(data_directory) and not os.path.isdir(os.path.join(certs_directory)):
        stat_info = os.stat(data_directory)
        uid = stat_info.st_uid
        gid = stat_info.st_gid
        os.mkdir(certs_directory)
        os.chown(certs_directory, uid, gid)
        os.chmod(certs_directory, 0o700)
        ret['changed'] = True

    ### Create private key and certificate
    if not os.path.isfile(os.path.join(certs_directory, cn + '.key')) or not os.path.isfile(os.path.join(certs_directory, cn + '.crt')):
        cmd = [
            'icinga2',
            'pki',
            'new-cert',
            '--cn', cn,
            '--key', os.path.join(certs_directory, cn + '.key'),
            '--cert', os.path.join(certs_directory, cn + '.crt'),
        ]
        rc, stdout, stderr = module.run_command(
            cmd,
            executable=None,
            use_unsafe_shell=False,
            encoding=None,
            data=None,
            binary_data=True,
            expand_user_and_vars=True,
        )
        ret['changed'] = True

    # Return values for the given mode + config
    mode_ret = dict()
    config_ret = dict()

    if mode == 'agent':
        mode_ret = agent_setup(module, cn, host, port, ticket, fingerprint, ignore_fingerprint, certs_directory)
    elif mode == 'master':
        mode_ret = master_setup(module, cn, ca_directory, certs_directory)

    config_ret = configure(module, cn, zones, sysconf_directory)
    module.warn("config ret " + str(config_ret))

    ### Collect information for return values
    ret.update(get_return_values(module, cn, ca_directory, certs_directory))

    # this one actually creates / pulls ca.crt
    #icinga2 pki request --host 192.168.122.113 --port 5665 --trustedcert /var/lib/icinga2/certs/trusted-parent.crt --ca /var/lib/icinga2/certs/ca.crt --key /var/lib/icinga2/certs/ansible-ubuntu24.key --cert /var/lib/icinga2/certs/ansible-ubuntu24.crt


    # Verify / test
    # While 
    # icinga2 pki verify --cert /var/lib/icinga2/certs/ansible-ubuntu24.crt  --cacert /var/lib/icinga2/certs/ca.crt → RC 2
    # still pending

    # Potential answers
    # critical/cli: CRITICAL: Certificate with CN 'ansible-ubuntu24' is NOT signed by CA: self-signed certificate (code 18)
    #   → RC 2
    #   → Error until certificate is signed
    #

    # Check if either setup or configuration had changes
    module.warn("mode" + str(mode_ret))
    module.warn("config" + str(config_ret))
    if any(r['changed'] for r in (mode_ret, config_ret)):
        ret['changed'] = True

    # Check if either setup or configuration had failures
    if 'fail_msg' in mode_ret:
        module.fail_json(
            **ret,
            msg=mode_ret['fail_msg']
        )
    elif 'fail_msg' in config_ret:
        module.fail_json(
            **ret,
            msg=config_ret['fail_msg']
        )

    module.exit_json(
        **ret,
    )


if __name__ == '__main__':
    main()
