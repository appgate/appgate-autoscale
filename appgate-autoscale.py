#!/usr/bin/env python3
"""
© 2019, AppGate.  All rights reserved.
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met: (a) redistributions
of source code must retain the above copyright notice, this list of conditions and
the disclaimer below, and (b) redistributions in binary form must reproduce the
above copyright notice, this list of conditions and the disclaimer below in the
documentation and/or other materials provided with the distribution.
THE CODE AND SCRIPTS POSTED ON THIS WEBSITE ARE PROVIDED ON AN “AS IS” BASIS AND
YOUR USE OF SUCH CODE AND/OR SCRIPTS IS AT YOUR OWN RISK.  APPGATE DISCLAIMS ALL
EXPRESS AND IMPLIED WARRANTIES, EITHER IN FACT OR BY OPERATION OF LAW, STATUTORY
OR OTHERWISE, INCLUDING, BUT NOT LIMITED TO, ALL WARRANTIES OF MERCHANTABILITY,
TITLE, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, ACCURACY, COMPLETENESS,
COMPATABILITY OF SOFTWARE OR EQUIPMENT OR ANY RESULTS TO BE ACHIEVED THEREFROM.
APPGATE DOES NOT WARRANT THAT SUCH CODE AND/OR SCRIPTS ARE OR WILL BE ERROR-FREE.
IN NO EVENT SHALL APPGATE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
RELIANCE, EXEMPLARY, PUNITIVE OR CONSEQUENTIAL DAMAGES, OR ANY LOSS OF GOODWILL,
LOSS OF ANTICIPATED SAVINGS, COST OF PURCHASING REPLACEMENT SERVICES, LOSS OF PROFITS,
REVENUE, DATA OR DATA USE, ARISING IN ANY WAY OUT OF THE USE AND/OR REDISTRIBUTION OF
SUCH CODE AND/OR SCRIPTS, REGARDLESS OF THE LEGAL THEORY UNDER WHICH SUCH LIABILITY
IS ASSERTED AND REGARDLESS OF WHETHER APPGATE HAS BEEN ADVISED OF THE POSSIBILITY
OF SUCH LIABILITY.

Autoscale an AppGate site on AWS, GCP and Azure.
"""
import shutil
import string
import argparse
import copy
import getpass
import http.client
import json
import tempfile
from json import loads as json_loads
from json import load as json_load
from json import dumps as json_dumps
from pathlib import Path
import logging
import os
import re
import ssl
import sys
from typing import Any, Dict, List, Optional, Set, Union, Iterable, Callable
import urllib.error
import urllib.parse
import urllib.request
import uuid
import subprocess

# Version of the AppGate gateway autoscale script
VERSION = '5.1.0'

log = logging.getLogger('appgate-autoscale')
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

# The minimum version this script was tested again
MINIMUM_PEER_API_VERSION = 5

# Appliances marked with this tag are chosen as the gateway template
# with a higher priority.
TEMPLATE_TAG = 'template'


def ask_for_password(username: str, provider: str) -> str:
    return getpass.getpass('Enter password for username {} '
                           'and provider name {}:'.format(username, provider))


class AdminError(Exception):
    pass


def _read_response(r: http.client.HTTPResponse) -> str:
    return r.read().decode('utf-8')


class Response:
    def __init__(self, status_code: int, content: str) -> None:
        self.status_code = status_code
        self.content = content

    @staticmethod
    def from_urllib_error(e: urllib.error.HTTPError) -> 'Response':
        return Response(status_code=e.code, content=e.fp.read().decode('utf-8'))  # type: ignore

    @staticmethod
    def from_http_response(r: http.client.HTTPResponse) -> 'Response':
        return Response(status_code=r.code, content=_read_response(r))  # type: ignore

    def json(self) -> dict:
        return json_loads(self.content)


class HTTPError(AdminError):
    """
    Mostly requests compatible error class to wrap urllib errors.
    To help porting code from requests to urllib.
    """

    def __init__(self, response: Response) -> None:
        super().__init__('HTTP Error {}: {}'.format(response.status_code, response.content))
        self.response = response

    @staticmethod
    def from_urllib_error(e: urllib.error.HTTPError) -> 'HTTPError':
        return HTTPError(Response.from_urllib_error(e))

    @staticmethod
    def from_http_response(r: http.client.HTTPResponse) -> 'HTTPError':
        return HTTPError(Response.from_http_response(r))


class Appliance:
    """
    Structure to represent an appliance with just the info we need to manage auto scaling.
    """
    def __init__(self, appliance_id: Optional[str], name: str, peer_hostname: str, roles: Set[str],
                 site: Optional[str], activated: bool, tags: List[str], raw: Dict[str, Any]) -> None:
        self.appliance_id = appliance_id
        self.name = name
        self.peer_hostname = peer_hostname
        self.roles = roles
        self.site = site
        self.activated = activated
        self.tags = tags
        self.raw = raw

    def __repr__(self) -> str:
        return '{}(name={!r}, peer_hostname={!r}, role={!r}, site={!r}, activated={!r}, tags={!r})'.format(
            self.__class__.__name__, self.name, self.peer_hostname, self.roles, self.site, self.activated,
            self.tags)

    @staticmethod
    def from_dict(data: dict) -> 'Appliance':
        all_roles = {'controller', 'logServer', 'gateway', 'logForwarder', 'iotConnector'}
        return Appliance(
            appliance_id=data.get('id'),
            name=data['name'],
            peer_hostname=data['peerInterface']['hostname'],
            roles={role for role in all_roles if data[role]['enabled'] if role in data},
            site=data.get('site'),
            activated=data['activated'],
            tags=data['tags'],
            raw=data
        )


class Admin:
    """
    The Admin class is used to handle all interactions with the controller REST API necessary
    for upgrades.
    """

    def __init__(self, url: str, verify: Union[bool, str], peer_api_version: Optional[int] = None) -> None:
        self.url = url
        self.verify = verify
        # If the peer api version is None it will be discovered automatically.
        self._peer_api_version = peer_api_version
        self._auth_token = None  # type: Optional[str]

    @property
    def peer_api_version(self) -> int:
        if self._peer_api_version is None:
            raise Exception('No peer API version set!')
        return self._peer_api_version

    @property
    def accept_header(self) -> str:
        header_format = 'application/vnd.cryptzone.peer-v{}+json' if self.peer_api_version < 7 else 'application/vnd.appgate.peer-v{}+json'
        return header_format.format(self.peer_api_version)

    def request(self, method: str, path: str, *, json: dict = None, headers: Dict[str, str] = None) -> Dict[str, Any]:
        headers = headers or {}
        if 'Accept' not in headers:
            headers['Accept'] = self.accept_header
        if 'Authorization' not in headers and self._auth_token:
            headers['Authorization'] = 'Bearer {}'.format(self._auth_token)

        data = None  # type: Optional[bytes]
        if json is not None:
            data = json_dumps(json).encode('utf-8')
            headers['Content-Type'] = 'application/json;'
            headers['Content-Length'] = str(len(data))

        req = urllib.request.Request('{}{}'.format(self.url, path), method=method)
        for key, value in headers.items():
            req.add_header(key, value)

        ssl_context = None  # type: Any
        cafile = None  # type: Any
        if isinstance(self.verify, str):
            cafile = self.verify
        elif not self.verify:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        try:
            r = urllib.request.urlopen(req, data, cafile=cafile, context=ssl_context)
        except urllib.error.HTTPError as e:
            if e.args and isinstance(e.args[0], ssl.SSLError):
                raise
            raise HTTPError.from_urllib_error(e) from e

        if r.status not in {200, 204}:
            raise HTTPError.from_http_response(r)

        if r.status == 200:
            content = r.read().decode('utf-8')
            return json_loads(content)
        else:
            return {}

    def _authenticate(self, username: str, password: str, provider: str, device_id: str) -> str:
        """
        Authenticates to the controller.
        Returns the auth token as a base64 string on success.
        """
        credentials = {
            'username': username,
            'password': password,
            'providerName': provider,
            'deviceId': device_id
        }
        auth_token = self.request('POST', '/admin/authentication', json=credentials)['token']
        return auth_token

    def _discover_peer_api_version(self) -> int:
        """
        Discover the peer API version by doing a request with a wrong request header
        and extracting the peer API version from the error response.
        """
        try:
            self.request('POST', '/admin/authentication', headers={'Accept': 'application/json'})
        except HTTPError as e:
            if e.response.status_code == 406:
                peer_api_version = e.response.json()['maxSupportedVersion']
                return peer_api_version
            else:
                raise
        raise AdminError('Failed to discover peer API version!')

    def authenticate(self, username: str, provider: str, device_id: str,
                     password_path: str, num_attempts: int = 3) -> None:
        if self._peer_api_version is None:
            log.info('Discovering peer API version for %s...', self.url)
            self._peer_api_version = self._discover_peer_api_version()
            log.info('Peer API version is {}'.format(self._peer_api_version))

        try:
            if os.path.isabs(password_path):
                abs_password_path = password_path
            else:
                abs_password_path = '{}/{}'.format(os.getcwd(), password_path)
            if not os.path.exists(abs_password_path):
                raise AdminError('No password executable found at: {}'.format(abs_password_path))
            admin_password_json = subprocess.check_output([abs_password_path]).decode()
            admin_password = json_loads(admin_password_json)['password']
        except subprocess.CalledProcessError as e:
            sys.exit(e.returncode)
        except ValueError:
            raise AdminError('Failed to get the admin password.')

        if not admin_password:
            admin_password = ask_for_password(username, provider)

        for _ in range(num_attempts):
            try:
                log.info('Authenticating to %s...', self.url)
                self._auth_token = self._authenticate(username, admin_password, provider, device_id)
                return
            except HTTPError as e:
                if e.response.status_code == 401:
                    log.warning('Invalid username or password!')
                    admin_password = ask_for_password(username, provider)
                    continue
                else:
                    raise AdminError('Authentication failed!') from e
        raise AdminError('Authentication failed!')

    def _authorize(self) -> str:
        """
        Authorizes and returns a new auth token with entitlements.
        """
        auth_token = self.request('GET', '/admin/authorization')['token']
        return auth_token

    def authorize(self) -> None:
        while True:
            log.info('Authorizing...')
            try:
                self._auth_token = self._authorize()
                return
            except HTTPError as e:
                message = e.response.json()['message']
                raise AdminError('Authorization failed: {}'.format(message)) from e

    def appliances(self) -> List[Appliance]:
        """
        Get all activated appliances.
        """
        appliances_data = self.request('GET', '/admin/appliances')['data']

        return [Appliance.from_dict(data)
                for data in appliances_data]

    def appliance(self, appliance_id: str) -> Appliance:
        """
        Get single appliance.
        """
        appliance_data = self.request('GET', '/admin/appliances/{}'.format(appliance_id))
        return Appliance.from_dict(appliance_data)

    def create_appliance(self, data: Dict[str, Any]) -> Appliance:
        return Appliance.from_dict(self.request('POST', '/admin/appliances', json=data))

    def export_appliance(self, appliance_id: str) -> dict:
        return self.request('POST', '/admin/appliances/{}/export'.format(appliance_id),
                            json={'provideCloudSSHKey': True})

    def delete_appliance(self, appliance_id: str) -> None:
        self.request('DELETE', '/admin/appliances/{}'.format(appliance_id))


def clone_appliance(appliance: Appliance, name: str, hostname: str, peer_hostname: str,
                    share_client_hostname: bool) -> Appliance:
    """
    Clone a given appliance configuration with some new unique parameters.
    """
    data = appliance.raw
    clone = copy.deepcopy(data)
    clone['name'] = name
    del clone['id']
    clone['hostname'] = hostname
    clone['peerInterface']['hostname'] = peer_hostname
    if not share_client_hostname:
        clone['clientInterface']['hostname'] = peer_hostname

    # Filter the template tag from the instance tags
    clone['tags'] = [tag for tag in appliance.tags if tag != TEMPLATE_TAG]

    return Appliance.from_dict(clone)


def parse_instance_id(name: str) -> Optional[str]:
    """
    Extract appliance instance id from appliance name, for example:
        gateway template - Autoscaling Instance i-09399cb01b94c4679
    Becomes:
        i-09399cb01b94c4679
    """
    m = re.match("^.* - Autoscaling Instance ([\w-]+)$", name)
    if m is not None:
        return m.group(1).strip()
    else:
        return None


def get(url: str, headers=None) -> str:
    req = urllib.request.Request(url, headers=headers if headers else {})
    return _read_response(urllib.request.urlopen(req))


def _admin(args) -> Admin:
    controller_url = 'https://{}:{}'.format(args.hostname, args.port)
    username = args.username
    provider = args.provider
    device_id = args.device_id
    if args.no_verify:
        verify = False
    elif args.cacert:
        verify = args.cacert
    else:
        verify = True
    peer_api_version = args.peer_api_version

    # Setup admin object to handle all communications with the controller.
    admin = Admin(controller_url, verify, peer_api_version=peer_api_version)
    try:
        admin.authenticate(username, provider, device_id, args.password_path)
    except urllib.error.URLError as e:
        if e.args and isinstance(e.args[0], ssl.SSLError):
            raise AdminError('Certificate verification failed, use the --cacert option to provide the controller\'s '
                             'CA certificate.')
        else:
            raise
    admin.authorize()

    if admin.peer_api_version < MINIMUM_PEER_API_VERSION:
        log.warning('The AppGate automatic seeding script is not supported for peer API '
                    ' versions less than {}, current API version is {}'.format(
            MINIMUM_PEER_API_VERSION, admin.peer_api_version))

    return admin


def _admin_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('hostname', help='AppGate Controller hostname or ip', default=None)
    parser.add_argument('--port', default=444, help='AppGate Controller admin port')
    parser.add_argument('--device-id', default=str(uuid.uuid4()),
                        help='Device id of the local machine, it will be generated at every run if not set')
    parser.add_argument('--username', default='admin', help='Admin username')
    parser.add_argument('--provider', default='local', help='Identity provider for the admin user')
    parser.add_argument('--no-verify', action='store_true', default=False,
                        help='Do NOT verify the controller\'s certificate')
    parser.add_argument('--cacert', default=None, help='Path to the controller\'s CA cert file')
    parser.add_argument('--peer-api-version', default=None, type=int, required=False,
                        help='Controller Peer API version, it will be auto-discovered if not set')
    return parser


def _parse_upscale_args(argv: List[str]):
    parser = _admin_parser('Seed a new gateway for autoscaling')
    parser.add_argument('-f', '--file', help='Destination file, default is stdout', default=None)
    parser.add_argument('-pp', '--password-path', help='path to the executable to get admin password', required=True)
    parser.add_argument('-s', '--site', help='site identifier', required=True)
    parser.add_argument('--appliance-hostname', help='hostname of the new appliance', default=None)
    parser.add_argument('--peer-hostname', help='Peer hostname for the new appliance', default=None)
    parser.add_argument('--instance-id', help='Instance id for the new autoscale instance', default=None)
    parser.add_argument('--share-client-hostname', action='store_true', default=False)
    parser.add_argument('-ui', '--use-ip-as-peer-hostname', help='use ip as a peer hostname for the new appliance',
                        action='store_true')
    return parser.parse_args(argv)


def _assign_instance_id(appliances: Iterable[Appliance]) -> str:
    """
    If no instance id is given, assign an instance ids by incrementing a positive integer.
    """
    instance_ids = (parse_instance_id(appliance.name) for appliance in appliances)
    instance_numbers = (int(instance_id) for instance_id in instance_ids
                        if instance_id and instance_id.isdigit())
    instance_number = max(instance_numbers, default=0) + 1
    return str(instance_number)


def find_template_gateway(appliances: List[Appliance], site: str) -> Appliance:
    # Only consider gateways in the given site
    templates = [appliance for appliance in appliances
                 if appliance.site == site and 'gateway' in appliance.roles]

    # Try to limit the search for a template to just inactive gateways
    active_templates = [appliance for appliance in templates
                        if not appliance.activated]
    if len(active_templates) > 0:
        templates = active_templates

    # Now narrow it down to gateways tagged with template
    tagged_templates = [appliance for appliance in templates
                        if TEMPLATE_TAG in appliance.tags]
    if len(tagged_templates) > 0:
        templates = tagged_templates

    # Find the template gateway
    try:
        template = next(iter(templates))
    except StopIteration:
        raise AdminError('Could not find an appropriate template gateway in site {}'.format(site))

    log.info('Found template gateway {} "{}" in site {}'.format(
        template.appliance_id, template.name, site))
    return template


def autoseed(admin: Admin, site: str, hostname: str, peer_hostname: str, instance_id: Optional[str] = None,
             share_client_hostname: bool = True) -> dict:
    """
    Automatically seed this appliance based on the first gateway in the given site.
    """
    appliances = admin.appliances()

    # Find the template gateway
    template_gateway = find_template_gateway(appliances, site)

    # Find a gateway with the same peer hostname, if there is one delete it, we are replacing it!
    site_gateways = [appliance for appliance in appliances
                     if appliance.site == site and 'gateway' in appliance.roles]
    matching_gateway = next(filter(lambda a: a.peer_hostname == peer_hostname, site_gateways), None)
    if matching_gateway is not None and matching_gateway.appliance_id is not None:
        log.info('Found a matching gateway with peer hostname {}, {} "{}", deleting it!'.format(
            peer_hostname, matching_gateway.appliance_id, matching_gateway.name))
        admin.delete_appliance(matching_gateway.appliance_id)

    # Assign an instance id if none is given
    if instance_id is None:
        instance_id = _assign_instance_id(site_gateways)

    # Finally, clone the template and create the new instance
    log.info('Creating autoscaling instance {}...'.format(instance_id))
    name = '{} - Autoscaling Instance {}'.format(template_gateway.name, instance_id)
    cloned_appliance = clone_appliance(template_gateway,
                                       name=name,
                                       hostname=hostname,
                                       peer_hostname=peer_hostname,
                                       share_client_hostname=share_client_hostname)
    new_gateway = admin.create_appliance(cloned_appliance.raw)

    if new_gateway.appliance_id:
        log.info('Created new gateway {} "{}"'.format(new_gateway.appliance_id, new_gateway.name))
        return admin.export_appliance(new_gateway.appliance_id)
    else:
        raise AdminError('Gateway {} has no appliance id: {}'.format(name, new_gateway))


def _get_cloud_provider():
    # Backwards compatibility for versions up to 5.0.1
    environment_type_path = Path('/mnt/boot/metadata/environment-type')
    try:
        return Path(environment_type_path).read_text().rstrip()
    except FileNotFoundError:
        pass

    kernel_cmd = dict(filter(lambda parts: len(parts) == 2,  # type: ignore
                             map(lambda kv: kv.split('=', maxsplit=1),
                                 Path('/proc/cmdline').read_text().split())))
    return kernel_cmd.get('cz-environment')


def check_already_activated() -> bool:
    """
    The appliance is already activated if has an appliance certificate
    provided by the controller.
    """
    return os.path.exists('/mnt/state/pki/appliance-cert.pem')


def upscale(argv: List[str]) -> None:
    if check_already_activated():
        log.info('Appliance already activated, nothing to do!')
        return

    args = _parse_upscale_args(argv)

    if args.peer_api_version is None:
        # If the script is running on an appliance, get the peer API version from there.
        try:
            with open('/mnt/state/config/current/remote.json') as f:
                remote_config = json_load(f)
                peer_api_version = remote_config['version']
            args.peer_api_version = peer_api_version
        except FileNotFoundError:
            pass

    admin = _admin(args)

    hostname = args.appliance_hostname
    instance_id = args.instance_id

    cloud_provider = _get_cloud_provider()

    if not hostname and cloud_provider:
        # Discovering public hostname
        hostname = _get_hostname(cloud_provider)

    if args.peer_hostname:
        peer_hostname = args.peer_hostname
    elif args.use_ip_as_peer_hostname and cloud_provider:
        peer_hostname = _get_host_ip(cloud_provider)
    else:
        peer_hostname = hostname

    if not instance_id and cloud_provider:
        instance_id = _get_instance_id(cloud_provider)

    seed = autoseed(admin, site=args.site, hostname=hostname, peer_hostname=peer_hostname,
                    share_client_hostname=args.share_client_hostname,
                    instance_id=instance_id)
    if args.file:
        # Always write seed to temporary file first and then move it to it's final destination
        # in order to do an atomic write.
        tmp_seed = tempfile.NamedTemporaryFile(prefix='seed-', suffix='.json', delete=False)
        with open(tmp_seed.name, 'wt') as f:
            json.dump(seed, f, indent=4)
        tmp_seed.close()
        shutil.move(tmp_seed.name, args.file)
    else:
        json.dump(seed, sys.stdout, indent=4)


def _get_hostname(cloud_service: str) -> str:
    if cloud_service == 'aws':
        hostname = get('http://169.254.169.254/latest/meta-data/public-hostname')
    elif cloud_service == 'azure':
        name = get('http://169.254.169.254/metadata/instance/compute/name?api-version=2017-03-01&format=text',
                   headers={"Metadata": "true"})
        location = get('http://169.254.169.254/metadata/instance/compute/location?api-version=2017-03-01&format=text',
                       headers={"Metadata": "true"})
        allow = string.ascii_letters + string.digits
        vm_name = re.sub('[^%s]' % allow, '', name)
        hostname = '{}.{}.cloudapp.azure.com'.format(vm_name, location)
    elif cloud_service == 'openstack':
        hostname = get('http://169.254.169.254/2009-04-04/meta-data/hostname')
    else:
        hostname = get('http://metadata.google.internal/computeMetadata/v1/instance/hostname',
                       headers={"Metadata-Flavor": "Google"})

    log.info('Discovered hostname {}'.format(hostname))
    return hostname


def _get_host_ip(cloud_service: str) -> str:
    if cloud_service == 'gcp':
        host_ip = get(
            'http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip',
            headers={"Metadata-Flavor": "Google"})
    elif cloud_service == 'openstack':
        host_ip = get('http://169.254.169.254/2009-04-04/meta-data/public-ipv4')
    else:
        host_ip = get(
            'http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-08-01&format=text',
            headers={"Metadata": "true"})

    log.info('Discovered host ip {}'.format(host_ip))
    return host_ip


def _get_instance_id(cloud_service: str) -> Optional[str]:
    if cloud_service == 'aws':
        try:
            instance_id = json_loads(get('http://169.254.169.254/latest/dynamic/instance-identity/document'))[
                'instanceId']

        except urllib.error.URLError:
            log.error('Could not discover instance id, will use an increasing counter...')
            instance_id = None
    elif cloud_service == 'azure':
        instance_id = get('http://169.254.169.254/metadata/instance/compute/vmId?api-version=2017-03-01&format=text',
                          headers={"Metadata": "true"})
    elif cloud_service == 'openstack':
        instance_id = get('http://169.254.169.254/2009-04-04/meta-data/instance-id')
    elif cloud_service == 'gcp':
        instance_id = get('http://metadata.google.internal/computeMetadata/v1/instance/id',
                          headers={"Metadata-Flavor": "Google"})
    elif cloud_service == 'configdrive':
        return None

    log.info('Discovered instance id {}'.format(instance_id))
    return instance_id


def _parse_downscale_args(argv: List[str]):
    parser = _admin_parser('Remove a gateway for autoscaling')
    parser.add_argument('-pp', '--password-path', help='path to the executable to get admin password', required=True)
    parser.add_argument('--instance-id', help='Autoscale instance id', default=None)
    return parser.parse_args(argv)


def downscale(argv: List[str]) -> str:
    args = _parse_downscale_args(argv)

    admin = _admin(args)

    # If the script is running on an appliance, get the appliance id from there.
    appliance_id = None  # type: Optional[str]
    try:
        with open('/mnt/state/config/current/remote.json') as f:
            remote_config = json_load(f)
            appliance_id = remote_config['id']
    except FileNotFoundError:
        pass

    if appliance_id:
        appliance = admin.appliance(appliance_id)

        # Get the instance id back from the name
        instance_id = parse_instance_id(appliance.name)
    else:
        # Else figure out the appliance id from the instance id
        cloud_provider = _get_cloud_provider()
        if cloud_provider:
            instance_id = _get_instance_id(cloud_service=cloud_provider)
        else:
            instance_id = args.instance_id

        if instance_id is None:
            raise AdminError('An instance id is required!')

        log.info('Removing instance {}...'.format(instance_id))

        # Find matching appliance
        try:
            appliance = next(appliance for appliance in admin.appliances()
                             if parse_instance_id(appliance.name) == instance_id)
        except StopIteration:
            raise AdminError('Could not find appliance with instance id {}'.format(instance_id))

    # Delete appliance
    if appliance.appliance_id:
        log.info('Deleting appliance {} "{}"...'.format(appliance.appliance_id, appliance.name))
        admin.delete_appliance(appliance.appliance_id)
    else:
        raise AdminError('Cannot delete appliance {}, it has no appliance id: {}'.format(appliance.name,
                                                                                         appliance))

    return 'Deleted autoscale instance {}: {} "{}"'.format(
        instance_id, appliance.appliance_id, appliance.name)


def _parse_bootstrap_args(argv: List[str]):
    """
    Optionally set values in the bootstrap script.
    It should be possible to not set any.
    """
    parser = argparse.ArgumentParser(description='Bootstrap an autoscaling script for your deployment')
    parser.add_argument('--hostname', default='', help='AppGate Controller hostname or ip')
    parser.add_argument('--share-client-hostname', action='store_true',
                        help='Client interface hostname will be taken from the gateway template\n'
                             'Each gateway will use the same value as for the peer hostname if not set')
    parser.add_argument('--port', default=444, help='AppGate Controller admin port')
    parser.add_argument('--username', default='admin', help='Admin username')
    parser.add_argument('--password', default='', help='Admin password')
    parser.add_argument('--cacert', default='', help='Path to the controller\'s CA cert file')
    parser.add_argument('--no-verify', action='store_true', default=False,
                        help='Do NOT verify the controller\'s certificate')
    parser.add_argument('--site', default='', help='site identifier')
    parser.add_argument('-f', '--file', help='Bootstrap output file, default to stdout', default=None)
    parser.add_argument('-ne', '--no-base64-encode', help='do not encode the output script to base64',
                        action='store_true')
    parser.add_argument('-ui', '--use-ip-as-peer-hostname', help='use ip as a peer hostname for the new appliance',
                        action='store_true')
    parser.add_argument('-nds', '--no-downscale-script', help='do not create the downscale script', action='store_true')
    parser.add_argument('--peer-hostname', help='Peer hostname for the new appliance', default=None)
    parser.add_argument('--appliance-hostname', help='hostname for the new appliance', default=None)
    args = parser.parse_args(argv)

    # Validate site id is a valid uuid
    if args.site:
        try:
            uuid.UUID(args.site, version=4)
        except ValueError:
            print('Not a valid site id:', args.site, file=sys.stderr)
            sys.exit(2)
    return args


def bootstrap(argv: List[str]) -> None:
    import base64
    import io
    import sys

    args = _parse_bootstrap_args(argv)

    ca_cert_content = ''
    if args.cacert:
        if os.path.exists(args.cacert):
            with open(args.cacert, mode='rt') as ft:
                ca_cert_content = ft.read()

    f = io.StringIO()
    print(r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import stat

CONTROLLER_HOSTNAME = '{hostname}'
CONTROLLER_PORT = '{port}'
ADMIN_USERNAME = '{username}'
SITE_ID = '{site}'
SHARE_CLIENT_HOSTNAME = {share_client_hostname}""".format(
        hostname=args.hostname,
        port=args.port,
        username=args.username,
        password=args.password,
        site=args.site,
        share_client_hostname=args.share_client_hostname
    ), file=f)

    if args.peer_hostname:
        print("PEER_HOSTNAME = '{}'".format(args.peer_hostname), file=f)
    else:
        print("PEER_HOSTNAME = None", file=f)

    if args.appliance_hostname:
        print("APPLIANCE_HOSTNAME = '{}'".format(args.appliance_hostname), file=f)
    else:
        print("APPLIANCE_HOSTNAME = None", file=f)

    if args.use_ip_as_peer_hostname:
        print("USE_IP_AS_PEER_HOSTNAME = {}".format(args.use_ip_as_peer_hostname), file=f)
    else:
        print("USE_IP_AS_PEER_HOSTNAME = False", file=f)

    if args.no_verify:
        print("CONTROLLER_CA_CERT = False", file=f)
    elif ca_cert_content:
        print(r"""
CONTROLLER_CA_CERT = '''\
{ca_cert_content}
'''""".format(ca_cert_content=ca_cert_content.strip()), file=f)
    else:
        print(r"CONTROLLER_CA_CERT = None", file=f)

    password_executable_variable = r"""
# The password executable script can be customized accordingly and the output should be in json format.
# For example:
# {{
#     "password": "<password>"
# }}
PASSWORD_EXECUTABLE_CONTENT = '''\
#!/bin/sh
# WARNING: It is strongly recommended to fetch the password from outside the startup script
echo '{output}'
'''
""".format(output=json.dumps({'password': args.password}))
    print(password_executable_variable, file=f)

    print(r"""
def main(args) -> str:
    password_executable = Path('/var/cache/cz-scripts/password-executable')
    password_executable.write_text(PASSWORD_EXECUTABLE_CONTENT)
    st = password_executable.stat()
    os.chmod(password_executable, st.st_mode | stat.S_IEXEC)

    if CONTROLLER_CA_CERT is None:
        verify_args = []
    if CONTROLLER_CA_CERT is False:
        verify_args = ['--no-verify']
    elif CONTROLLER_CA_CERT:
        ca_cert_path = Path('/tmp/ca-cert.pem')
        ca_cert_path.write_text(CONTROLLER_CA_CERT)
        verify_args = ['--cacert', str(ca_cert_path)]

    def base_command(action):
        cmd = ['/usr/share/admin-scripts/appgate-autoscale.py', action]
        cmd.extend([CONTROLLER_HOSTNAME,
                    '--port', CONTROLLER_PORT,
                    '--username', ADMIN_USERNAME,
                    '--password-path', str(password_executable)])
        cmd.extend(verify_args)
        return cmd""", file=f)

    if not args.no_downscale_script:
        print(r"""
    downscale_cmd = base_command('downscale')
    downscale_path = Path('/var/cache/cz-scripts/shutdown-script')
    downscale_path.write_text(f'''\
#!/bin/sh
{" ".join(map(str, downscale_cmd))}
''')
    st = downscale_path.stat()
    os.chmod(downscale_path, st.st_mode | stat.S_IEXEC)
    print(f'Downscale script created at {downscale_path}')
""", file=f)

    print("""\
    upscale_cmd = base_command('upscale')
    upscale_cmd.extend(['--site', SITE_ID,
                        '--file', '/home/cz/seed.json'])
    if SHARE_CLIENT_HOSTNAME:
        upscale_cmd.append('--share-client-hostname')

    if PEER_HOSTNAME:
        upscale_cmd.extend(['--peer-hostname', PEER_HOSTNAME])

    if APPLIANCE_HOSTNAME:
        upscale_cmd.extend(['--appliance-hostname', APPLIANCE_HOSTNAME])

    if USE_IP_AS_PEER_HOSTNAME:
        upscale_cmd.append('--use-ip-as-peer-hostname')

    print(' '.join(map(str, upscale_cmd)))
    try:
        return subprocess.run(upscale_cmd, check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)


if __name__ == '__main__':
    main(sys.argv[1:])
""", file=f)

    f.seek(0)
    meta_script = f.read()
    if len(meta_script) > 16384:
        raise AdminError('Autoscale script size is too big ({} > 16384) to fit in userdata!'.format(len(meta_script)))

    if not args.no_base64_encode:
        b64_meta_script = base64.b64encode(meta_script.encode())
        meta_script = b64_meta_script.decode()

    if args.file:
        with open(args.file, 'wt') as fout:
            fout.write(meta_script)
        os.chmod(args.file, 0o750)
    else:
        sys.stdout.write(meta_script)


def print_version(_: List[str]) -> None:
    print(VERSION)
    sys.exit(1)


def main() -> None:
    try:
        action = sys.argv[1]
    except IndexError:
        log.error('Missing action argument, one of: upscale, downscale, bootstrap')
        sys.exit(1)

    actions = {
        'upscale': upscale,
        'downscale': downscale,
        'bootstrap': bootstrap,
        '--version': print_version
    }  # type: Dict[str, Callable]
    try:
        action_fn = actions[action]
    except KeyError:
        log.error('Invalid action, got {} expected one of: {}'.format(
            action, ', '.join(sorted(actions.keys()))))
        sys.exit(1)

    try:
        action_fn(sys.argv[2:])
    except KeyboardInterrupt:
        log.info('Interrupted by user')
        sys.exit(2)
    except AdminError as e:
        log.error('Autoscale failed: {}'.format(str(e)))
        sys.exit(1)


if __name__ == '__main__':
    main()
