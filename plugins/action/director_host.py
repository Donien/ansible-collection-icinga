from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleUndefinedVariable
from ansible.module_utils.six import string_types
from ansible.module_utils._text import to_text
from ansible.plugins.action import ActionBase


import json
import requests
import urllib.parse


#from ansible_collections.icinga.icinga.plugins.module_utils.parse import (
#    IcingaDirectorVerify,
#)


def make_api_call(method, endpoint, params=None, data=None):
    headers = {
        'Accept': 'application/json',
    }
    auth=(DIRECTOR_USERNAME, DIRECTOR_PASSWORD)

    response = requests.request(
        method,
        DIRECTOR_URL + endpoint,
        verify=DIRECTOR_VERIFY,
        headers=headers,
        auth=auth,
        params=params,
        json=data,
    )
    params=params

    return response


def get_host(name, resolved=False):
    params   = {
                 'name': name,
                 'resolved': 1 if resolved else 0,
               }
    payload  = urllib.parse.urlencode(params, safe='/', quote_via=urllib.parse.quote)
    response = make_api_call('GET', '/host', params=payload)
    js = response.json()

    return js


def get_host_object(name, resolved=False):
    js = get_host(name, resolved=resolved)
    if js['object_type'] != 'object':
        raise ValueError(f"'{name}' is not a host object!")

    return js


def get_host_template(name, resolved=False):
    js = get_host(name, resolved=resolved)
    if js['object_type'] != 'template':
        raise ValueError(f"'{name}' is not a host template!")

    return js


def get_hosts():
    response = make_api_call('GET', '/hosts')
    return response.json()['objects']


def get_host_templates():
    response = make_api_call('GET', '/hosts/templates')
    return response.json()['objects']


def validate_host_template(data):
    ''' Validate if data passed is valid for a host template as compared to the Icinga Director web interface '''

    # Make sure all templates specified exist.

    if 'imports' in data:
        for template in data['imports']:
            js = get_host_template(template)

    forbidden_keys = [
        'address',
        'address6',
        'display_name',
        'disabled',
    ]

    for key in forbidden_keys:
        if key in data:
            raise KeyError(f'\'{key}\' is not allowed in templates!')


def validate_host(data):
    ''' Validate if data passed is valid for a host object as compared to the Icinga Director web interface '''

    # Make sure all templates specified exist. Also check if at least one provides a check command
    check_command_set = False
    if 'imports' in data:
        for template in data['imports']:
            js = get_host_template(template, resolved=True)
            if 'check_command' in js:
                check_command_set = True

    if not check_command_set:
        raise ValueError(f'None of the imported templates provides the \'check_command\' attribute')

    forbidden_keys = [
        'check_command',
        'check_interval',
        'check_period',
        'check_timeout',
        'enable_active_checks',
        'enable_passive_checks',
        'max_check_attempts',
    ]

    for key in forbidden_keys:
        if key in data:
            raise KeyError(f'\'{key}\' is not allowed in host objects!')


def delete_host(data):
    ''' Deletes a host '''

    # Initialize results dict to return to 'main' function
    result = { 'changed': False }

    params = {
        'name': data['object_name']
    }
    payload  = urllib.parse.urlencode(params, safe='/', quote_via=urllib.parse.quote)
    response = make_api_call('DELETE', '/host', params=payload)

    if response.status_code == 200:
        result['msg'] = f'Successfully removed \'{data["object_name"]}\' of type \'{data["object_type"]}\'!'
    elif response.status_code == 500:
        result['msg'] = f'Could not remove \'{data["object_name"]}\' of type \'{data["object_type"]}\'.\nDirector error message: {response.json()["error"]}'
        result['failed'] = True

    return result


def create_host(data):
    # Initialize results dict to return to 'main' function
    result = { 'changed': False }

    # Do some validation here
    # ...

    # Validate data
    if data['object_type'] == 'object':
        validate_host(data)
    elif data['object_type'] == 'template':
        validate_host_template(data)

    # Existing
    needs_update  = False
    exists        = False
    existing_data = get_host(data['object_name'], resolved=False)

    # Ignore fields. Won't handle for now
    if not 'error' in existing_data:
        exists = True
        fields = existing_data.pop('fields')

    # Return early if host/template already exists and no changes need to be made
    if existing_data == data:
        return result

    # Make API call
    if exists:
        params = {
            'name': data['object_name'],
        }
        payload  = urllib.parse.urlencode(params, safe='/', quote_via=urllib.parse.quote)
        response = make_api_call('POST', '/host', params=payload, data=data)
    else:
        response = make_api_call('POST', '/host', data=data)

    # Do some post processing (validate success and alike)
    if response.status_code == 200:
        result['changed'] = True
        result['msg'] = f'Successfully updated \'{data["object_name"]}\' of type \'{data["object_type"]}\''
    elif response.status_code == 201:
        result['changed'] = True
        result['msg'] = f'Successfully created \'{data["object_name"]}\' of type \'{data["object_type"]}\''

    return result


class ActionModule(ActionBase):
    ''' Print statements during execution '''

    TRANSFERS_FILES = False
    #_VALID_ARGS = frozenset(('msg', 'var', 'verbosity'))

    def run(self, tmp=None, task_vars=None):
        global DIRECTOR_URL
        global DIRECTOR_USERNAME
        global DIRECTOR_PASSWORD
        global DIRECTOR_VERIFY

        #for key, value in task_vars.items():
        #    print(key)

        validation_result, new_module_args = self.validate_argument_spec(
            argument_spec={
                'url': { 'type': 'str', 'required': True },
                'username': { 'type': 'str', 'required': True },
                'password': { 'type': 'str', 'required': True },
                'validate_certs': { 'type': 'bool', 'default': True },

                'state': { 'type': 'str', 'choice': [ 'present', 'absent' ], 'default': 'present' },
                'name': { 'type': 'raw', 'required': True },
                'type': { 'type': 'str', 'default': 'object' },
                'ipv4': { 'type': 'str' },
                'ipv6': { 'type': 'str' },
                'command': { 'type': 'str' },
                'imports': { 'type': 'list', 'elements': 'str' },
                'vars': { 'type': 'dict' },

                'zone': { 'type': 'str', 'default': None },
                'has_agent': { 'type': 'bool' },
                'accept_config': { 'type': 'bool' },
                'master_should_connect': { 'type': 'bool' },
            },

            # Specify which options must (not) be used in conjunction, standalone, etc.
            # https://docs.ansible.com/ansible/latest/dev_guide/developing_program_flow_modules.html#argument-spec-dependencies
            #mutually_exclusive = [
            #    ('msg', 'var'),
            #],
            #required_by= {
            #               'test': { 'test_case', 'test_platform' },
            #},
            required_if = [
                ('type', 'object', ('ipv4', 'ipv6'), True),
            ],
            #required_one_of = [
            #    ('ipv4', 'ipv6'),
            #],
        )

        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        #print(new_module_args)
        #print(validation_result.validated_parameters)

        DIRECTOR_URL      = new_module_args.pop('url')
        DIRECTOR_USERNAME = new_module_args.pop('username')
        DIRECTOR_PASSWORD = new_module_args.pop('password')
        DIRECTOR_VERIFY   = new_module_args.pop('validate_certs')

        # Change key names within dictionary to be easily passed to functions
        new_module_args['object_name']   = new_module_args.pop('name')
        new_module_args['object_type']   = new_module_args.pop('type')
        new_module_args['address']       = new_module_args.pop('ipv4')
        new_module_args['address6']      = new_module_args.pop('ipv6')
        new_module_args['check_command'] = new_module_args.pop('command')

        # Remove keys with 'None' value
        new_module_args = { key: value for key, value in new_module_args.items() if value != None }

        # Decide what to do
        state = new_module_args.pop('state')

        if state == 'present':
            # Create / Update host
            result.update(create_host(new_module_args))

        elif state == 'absent':
            # Delete host
            result.update(delete_host(new_module_args))

        #for x in range(20):
        #    print("host_template_{:02d}".format(x))

        #print(result)
        return result
