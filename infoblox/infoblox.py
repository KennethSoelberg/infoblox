from typing import List, Tuple
from ipaddress import ip_network
import requests
import urllib3

from infoblox.infoblox_exceptions import *
from .speciel_characters import speciel_characters_dict


class Infoblox:

    def __init__(self, ip: str, username: str, password: str, network_view: str, wapi_version: str, ssl=True):
        if not ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._base_url = f'https://{ip}/wapi/v{wapi_version}/'
        self._username = username
        self._password = password
        self._cookie = False
        self._grid_id = self._get_grid_id()
        self._settings = {'cookies': self._cookie, 'verify': False}
        self._fixed_ip_cache = {}
        self._network_view = network_view

    def __exit__(self, exc_type, exc_val, exc_tb):
        requests.post(f'{self._base_url}{self._grid_id}?_function=restartservices', **self._settings)

    def __enter__(self):
        return self

    def _convert_speciel_characters(self, characters: str) -> str:
        for letter in speciel_characters_dict:
            characters = characters.replace(letter, speciel_characters_dict[letter])
        return characters

    def _delete(self, url: str) -> requests:
        r = requests.delete(f'{self._base_url}{url}', **self._settings)
        return r

    def _delete_fixed_ip(self, ref: str) -> bool:
        r = requests.delete(f'{self._base_url}{ref}', **self._settings)
        if r.status_code == 200:
            return True
        else:
            return False

    def _get(self, url: str, data: dict = {}) -> requests:
        if data:
            r = requests.get(f'{self._base_url}{url}', json=data, **self._settings)
        else:
            r = requests.get(f'{self._base_url}{url}', **self._settings)
        return r

    def _get_grid_id(self) -> str:
        r = requests.get(f'{self._base_url}grid', auth=(self._username, self._password), verify=False)
        self._cookie = r.cookies
        return r.json()[0]['_ref']

    def _post(self, url: str, data: dict = {}) -> requests:
        if data:
            r = requests.post(f'{self._base_url}{url}', json=data, **self._settings)
        else:
            r = requests.post(f'{self._base_url}{url}', **self._settings)
        return r

    def _put(self, url: str, data: dict = {}) -> requests:
        if data:
            r = requests.put(f'{self._base_url}{url}', json=data, **self._settings)
        else:
            r = requests.put(f'{self._base_url}{url}', **self._settings)
        return r

    def delete_fixed_ip(self, mac: str = '', ref: str = '') -> dict:
        deleted_fiex_ips = {}
        if mac:
            mac = mac.lower()
            try:
                fixed_ip_data = self._fixed_ip_cache[mac]
            except KeyError:
                fixed_ip_data, status_code = self.get_fixed_ip(mac=mac)

            for fixed_ip in fixed_ip_data:
                ip = fixed_ip['_ref'].split(':')[1].split('/')[0]
                deleted_fiex_ips[ip] = self._delete_fixed_ip(ref=fixed_ip['_ref'])
        elif ref:
            ip = ref.split(':')[1].split('/')[0]
            deleted_fiex_ips[ip] = self._delete_fixed_ip(ref=ref)

        return deleted_fiex_ips

    def delete_network(self, ip: str) -> requests:
        try:
            ref = self.get_network(ip=ip).json()[0]['_ref']
        except IndexError:
            raise NetworkDoesNotExist(f'Not network exist with ip:{ip}')

        r = self._delete(url=ref)
        return r

    def close(self):
        self._post(url=f'{self._grid_id}?_function=restartservices')

    def create_network(self, ip: str, netmask_bits: str, comment: str, members: List[dict],
                       options: List[dict]) -> requests:
        data = {'network': f'{ip}/{netmask_bits}',
                'comment': comment,
                'network_view': self._network_view,
                'options': options,
                'members': members,
                }
        r = self._post(url=f'network', data=data)
        return r

    def create_range(self, ip: str, netmask_bits: str, member: dict) -> requests:
        network = f'{ip}/{netmask_bits}'
        hosts = list(ip_network(network).hosts())

        data = {'network': network,
                'network_view': self._network_view,
                'start_addr': str(hosts[0]),
                'end_addr': str(hosts[-1]),
                'member': member,
                }
        return self._post(url='range', data=data)

    def create_fix_ip(self, ip: str, mac: str, name: str, comment: str) -> requests:
        r = self._post(url=f'fixedaddress?mac={mac}&ipv4addr={ip}&name={name}&comment={comment}')
        return r

    def get_all_networks(self, max_results: int = 20000,
                         return_fiedls: str = 'network,netmask,ipv4addr,options') -> requests:
        r = self._get(url=f'network?_max_results={max_results}&_return_fields={return_fiedls}')
        return r

    def get_fixed_ip(self, mac: str, return_fields: str = 'ipv4addr,mac,name,comment') -> requests:
        r = self._get(url=f'fixedaddress?mac={mac}&_return_fields={return_fields}')
        if r.status_code == 200:
            self._fixed_ip_cache[mac] = [fixed_ip['_ref'] for fixed_ip in r.json()]
        return r

    def get_ip_info(self, ip: str) -> dict:
        r = self._get(url=f'ipv4address?ip_address={ip}')
        data = r.json()
        if r.status_code == 200 and data:
            return data
        else:
            return {}

    def get_network(self, ip, return_fiedls: str = 'network,netmask,ipv4addr,options') -> requests:
        return self._get(url=f'network?ipv4addr={ip}&_return_fields={return_fiedls}')

    def update_dns(self, dns_servers: list, ref: str):
        dns_string = ','.join(dns_servers)
        data = {'options': [
            {
                "name": "domain-name-servers",
                "num": 6,
                "use_option": True,
                "value": dns_string,
                "vendor_class": "DHCP"
            }]}

        return requests.put(f'{self._base_url}{ref}', json=data, **self._settings)
