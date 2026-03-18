from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
'''

EXAMPLES = r'''
'''

RETURN = r'''
'''

import glob
import os


def agent_setup(module, cn, host, port, ticket, certs_directory):
    changed = False
    r = dict()

    ### Get parent certificate
    cmd = [
        "icinga2",
        "pki",
        "save-cert",
        "--host",
        host,
        "--port",
        str(port),
        "--trustedcert",
        os.path.join(certs_directory, "trusted-parent.crt"),
    ]
    if not glob.glob(os.path.join(certs_directory, "trusted-parent.crt")):
        r['rc'], r['stdout'], r['stderr'] = module.run_command(
            cmd,
            executable=None,
            use_unsafe_shell=False,
            encoding=None,
            data=None,
            binary_data=True,
            expand_user_and_vars=True,
        )
        changed = True

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
        "icinga2",
        "pki",
        "request",
        "--host", host,
        "--port", str(port),
        "--trustedcert", os.path.join(certs_directory, "trusted-parent.crt"),
        "--ca", os.path.join(certs_directory, "ca.crt"),
        "--key", os.path.join(certs_directory, cn + ".key"),
        "--cert", os.path.join(certs_directory, cn + ".crt"),
    ]
    if ticket:
        cmd.extend(["--ticket", ticket])

    r['rc'], r['stdout'], r['stderr'] = module.run_command(
        cmd,
        executable=None,
        use_unsafe_shell=False,
        encoding=None,
        data=None,
        binary_data=True,
        expand_user_and_vars=True,
    )


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent']),
            cn=dict(required=True, type='str'),
            host=dict(required=True, type='str'),
            port=dict(default=5665, type='int'),
            ticket=dict(type='str', no_log=True),


            # Use that to verify
            finger_print=dict(type='str'),
            ignore_finger_print=dict(default=False, type='bool'),
        )
    )

    data_directory = "/var/lib/icinga2"
    certs_directory = os.path.join(data_directory, "certs")

    cn     = module.params['cn']
    host   = module.params['host']
    port   = module.params['port']
    ticket = module.params['ticket']

    r = dict(
        changed = True,
    )
    cmd = None

    ### Create certs/ if not present
    if os.path.isdir(data_directory) and not os.path.isdir(os.path.join(certs_directory)):
        stat_info = os.stat(data_directory)
        uid = stat_info.st_uid
        gid = stat_info.st_gid
        os.mkdir(certs_directory)
        os.chown(certs_directory, uid, gid)
        os.chmod(certs_directory, 0o700)

    ### Create private key and certificate
    if not os.path.isfile(os.path.join(certs_directory, cn + ".key")) or not os.path.isfile(os.path.join(certs_directory, cn + ".crt")):
        cmd = [
            "icinga2",
            "pki",
            "new-cert",
            "--cn", cn,
            "--key", os.path.join(certs_directory, cn + ".key"),
            "--cert", os.path.join(certs_directory, cn + ".crt"),
        ]
        r['rc'], r['stdout'], r['stderr'] = module.run_command(
            cmd,
            executable=None,
            use_unsafe_shell=False,
            encoding=None,
            data=None,
            binary_data=True,
            expand_user_and_vars=True,
        )

    agent_setup(module, cn, host, port, ticket, certs_directory)

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

    module.exit_json(
        **r,
        cmd=cmd,
    )


if __name__ == '__main__':
    main()
