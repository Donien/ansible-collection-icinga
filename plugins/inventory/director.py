# -*- coding: utf-8 -*-
# pylint: disable=consider-using-f-string,super-with-arguments,attribute-defined-outside-init,too-many-instance-attributes


from urllib.parse import urlparse
from requests.auth import HTTPBasicAuth
from requests.exceptions import SSLError, RequestException
import requests

from ansible.plugins.inventory import BaseInventoryPlugin, Cacheable, Constructable, to_safe_group_name
from ansible.module_utils._text import to_bytes

DOCUMENTATION = '''
    name: director
    short_description: Icinga Director inventory source
    requirements:
        - requests >= 1.1
    description:
        - Get inventory hosts from Icinga Director.
        - Uses Icinga Directors's API to get information about hosts.
        - The use of a custom filter is possible.
        - Uses a YAML configuration file that ends with ``director.(yml|yaml)``.
    extends_documentation_fragment:
        - constructed
        - inventory_cache
    options:
      plugin:
        description: Token that ensures this is a source file for the C(director) plugin.
        required: true
        choices: ['icinga.icinga.director']
      url:
        description:
          - URL to the Icinga Director endpoint of the Icinga Web 2 server.
          - If needed, pass a different port in the form of https://localhost:5678/icingaweb2/director
        default: 'https://localhost/icingaweb2/director'
      user:
        description:
          - The name of the user who accesses the Icinga Director API.
        required: true
      password:
        description:
          - The password of the user who accesses the Icinga Director API.
        required: true
      validate_certs:
        description:
          - Whether to validate Icinga Director API certificates.
        type: boolean
        default: true
      group_prefix:
        description:
          - Prefix to apply to Icinga Director specific groups.
          - By default hosts are also grouped by their zones.
          - This prefix applies to both attributes, groups and zone.
          - Results in groups named like C(PREFIX+GROUP) and C(PREFIX+ZONE+VALUE).
        type: string
        default: director_
      vars_prefix:
        description:
          - Prefix to apply to host variables.
          - Only affects Icinga Director host specific attributes.
        type: string
        default: director_
      ansible_user_var:
        description:
          - The hosts' attribute to set as C(ansible_user).
        type: string
      want_ipv4:
        description:
          - Whether C(ansible_host) should be set to the host's C(address) attribute.
          - C(want_ipv4) takes precedence over C(want_ipv6).
        type: bool
        default: false
      want_ipv6:
        description:
          - Whether C(ansible_host) should be set to the host's C(address6) attribute.
          - C(want_ipv4) takes precedence over C(want_ipv6).
        type: bool
        default: false
'''

EXAMPLES = '''
# inventory-icinga_director.yml
plugin: icinga.icinga.director
url: https://icinga.example.com/icingaweb2/director
user: ansibleinventory
password: changeme

# director.yaml
plugin: icinga.icinga.director
url: https://icinga.example.com/director
user: ansibleinventory
password: changeme
validate_certs: false


### Variables here are refered to without their added prefix
# Set Ansible's variable 'ansible_user' equal to the host's variable 'ansible_user'
ansible_user_var: vars.ansible_user

# Create groups with name 'director_distribution' + '_{VALUE OF VARIABLE}' and add hosts accordingly
keyed_groups:
  - prefix: "director_distribution"
    key: vars.distribution
'''



#class InventoryModule(BaseInventoryPlugin):
class InventoryModule(BaseInventoryPlugin, Cacheable, Constructable):
    NAME = 'director'

    def verify_file(self, path):
        ''' return true/false if this is possibly a valid file for this plugin to consume '''
        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(('director.yaml', 'director.yml')):
                valid = True
            else:
                self.display.vvv('Skipping due to inventory source not ending in "icinga.yaml" nor "icinga.yml"')
        return valid


    def _get_recursive_sub_element(self, d, key_string):
        delimiters     = [ '.', '[', ']' ]
        post_delimiter = '...'
        final_keys     = list()
        new_d          = d

        for delimiter in delimiters:
            key_string = key_string.replace(delimiter, post_delimiter)

        keys = key_string.split(post_delimiter)

        # Remove empty entries and cast numbers to integers
        for key in keys:
            if not key:
                continue
            if key.isdigit():
                key = int(key)
            else:
                key = key.strip('\'').strip('"')
            final_keys.append(key)

        # Recurse into structure
        for index, key in enumerate(final_keys):
            try:
                new_d = new_d[key]
            except IndexError:
                self.display.vvvv(f'Structure \'{d}\' has no index \'{index}\' for sub-structure \'{new_d}\'.')
                raise
            except (KeyError, TypeError):
                self.display.vvvv(f'Strucutre \'{d}\' has no key \'{key}\' for sub-structure \'{new_d}\'.')
                raise

        return new_d


    def _get_session(self):
        self.session         = requests.session()
        self.session.auth    = HTTPBasicAuth(to_bytes(self.director_user), to_bytes(self.director_password))
        self.session.headers = {
                                 'Accept': 'application/json',
                               }
        self.session.verify  = self.validate_certs
        return self.session


    def _get_hosts(self):
        s = self._get_session()

        # Validate connection via API URL
        try:
            s.get(self.api_url)
        except SSLError:
            self.display.vvv('SSL Error: You may want to trust the certificate or pass \'validate_certs: false\'')
            raise
        except RequestException:
            self.display.vvv('Error accessing \'{self.api_url}\'.')
            raise

        params = {
            "resolved": True,
            "withNull": True,
        }
        response = s.post(self.api_url + '/hosts', params=params)

        if response.status_code == 401:
            raise ValueError(f'Something went wrong. HTTP status code: \'{response.status_code}\'. You are unauthorized!')
        if response.status_code != 200:
            raise ValueError(f'Something went wrong. HTTP status code: \'{response.status_code}\'.')

        hosts = response.json()['objects']
        return hosts


    def _populate_inventory(self, hosts):
        # Always add keyed groups for attribute 'zone'
        zone_wanted = True
        for keyed_group in self.keyed_groups:
            if 'key' in keyed_group and keyed_group['key'] == 'zone':
                zone_wanted = False
                break

        if zone_wanted:
            zone_key = {'prefix': self.group_prefix + 'zone', 'key': 'zone'}
            self.keyed_groups.append(zone_key)

        for host in hosts:
            host_name = host['object_name']
            host_vars = host

            # Add groups and make current host a member based on its 'groups' attribute
            for group in host_vars['groups']:
                group_name = to_safe_group_name(self.group_prefix + 'group_' + group)
                self.inventory.add_group(group_name)
                self.inventory.add_host(host_name, group_name)

            # Add host to group 'ungrouped' if it does not belong to a group
            if not host_vars['groups']:
                self.inventory.add_host(host_name, )

            # Set attributes as host variables
            for key, value in host_vars.items():
                self.inventory.set_variable(host_name, f'{self.vars_prefix}{key}', value)

            # Set 'ansible_host' to IP address if requested
            if self.want_ipv4 and host_vars['address']:
                self.inventory.set_variable(host_name, 'ansible_host', host_vars['address'])
                self.display.vvv(f'Set attribute \'address\' as \'ansible_host\' for host \'{host_name}\'.')
            elif self.want_ipv6 and host_vars['address6']:
                self.inventory.set_variable(host_name, 'ansible_host', host_vars['address6'])
                self.display.vvv(f'Set attribute \'address6\' as \'ansible_host\' for host \'{host_name}\'.')

            # Set 'ansible_user' if requested and defined in the Icinga Director
            if self.ansible_user:
                ansible_user_value = None
                try:
                    ansible_user_value = self._get_recursive_sub_element(host_vars, self.ansible_user)
                except (IndexError, KeyError, TypeError):
                    self.display.vvv(f'Could not set \'{self.ansible_user}\' as \'ansible_user\' for host \'{host_name}\'.')

                # Set 'ansible_user'
                if ansible_user_value:
                    self.inventory.set_variable(host_name, 'ansible_user', ansible_user_value)

            # Add composite vars
            self._set_composite_vars(self.compose, host_vars, host_name, strict=self.strict)

            # Add composed groups
            self._add_host_to_composed_groups(self.groups, host_vars, host_name, strict=self.strict)

            # Add keyed_groups
            self._add_host_to_keyed_groups(self.keyed_groups, host_vars, host_name, strict=self.strict)


    def _validate_url(self, url):
        valid = False

        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme and parsed_url.netloc and str(parsed_url.path).endswith('director'):
                valid = True
        except ValueError:
            pass

        return valid


    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        # Read config options from file for futher use
        self._read_config_data(path)

        # Set attributes based on parsed file
        self.director_url      = self.get_option('url').strip('/')
        self.director_user     = self.get_option('user')
        self.director_password = self.get_option('password')
        self.validate_certs    = self.get_option('validate_certs')
        self.group_prefix      = self.get_option('group_prefix')
        self.vars_prefix       = self.get_option('vars_prefix')
        self.want_ipv4         = self.get_option('want_ipv4')
        self.want_ipv6         = self.get_option('want_ipv6')
        self.ansible_user      = self.get_option('ansible_user_var')

        # Related to Ansible's Constructable
        self.compose           = self.get_option('compose')
        self.groups            = self.get_option('groups')
        self.keyed_groups      = self.get_option('keyed_groups')
        self.strict            = self.get_option('strict')

        # Build API URL and validate
        self.api_url           = f'{self.director_url}'
        if not self._validate_url(self.api_url):
            raise ValueError(f'\'{self.api_url}\' is not a valid URL.')

        # Check if cache is available and should be used
        cache_key              = self.get_cache_key(path)
        use_cache              = self.get_option("cache") and cache
        update_cache           = self.get_option("cache") and not cache

        hosts = None

        # Get hosts from cache if available and recent
        if use_cache:
            try:
                hosts = self._cache[cache_key]
                self.display.vvv('Using existing cache.')
            except KeyError:
                self.display.vvv('Creating/updating cache.')
                update_cache = True

        if not hosts:
            # Get hosts from Icinga Director
            hosts = self._get_hosts()

        if update_cache:
            self._cache[cache_key] = hosts

        self._populate_inventory(hosts)
