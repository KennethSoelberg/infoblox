import requests
import urllib3

from typing import List, Tuple

from .speciel_characters import speciel_characters_dict


class Infoblox:

    def __init__(self, ip: str, username: str, password: str, wapi_version: str, ssl=True):
        if not ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._base_url = f'https://{ip}/wapi/{wapi_version}/'
        self._username = username
        self._password = password
        self._cookie = False
        self._grid_id = self._get_grid_id()
        self._settings = {'cookies': self._cookie, 'verify': False}
        self._fixed_ip_cache = {}

    def __exit__(self, exc_type, exc_val, exc_tb):
        requests.post(f'{self._base_url}{self._grid_id}?_function=restartservices', **self._settings)

    def __enter__(self):
        return self

    def _convert_speciel_characters(self, characters: str) -> str:
        for letter in speciel_characters_dict:
            characters = characters.replace(letter, speciel_characters_dict[letter])
        return characters

    def _get_grid_id(self) -> str:
        r = requests.get(f'{self._base_url}grid', auth=(self._username, self._password), verify=False)
        self._cookie = r.cookies
        return r.json()[0]['_ref']

    def _delete_fixed_ip(self, ref: str) -> bool:
        r = requests.delete(f'{self._base_url}{ref}', **self._settings)
        if r.status_code == 200:
            return True
        else:
            return False

    def close(self):
        requests.post(f'{self._base_url}{self._grid_id}?_function=restartservices', **self._settings)

    def get_fixed_ip(self, mac: str) -> Tuple[List[dict], int]:

        return_fields = 'ipv4addr,mac,name,comment'
        r = requests.get(f'{self._base_url}fixedaddress?mac={mac}&_return_fields={return_fields}', **self._settings)
        if r.status_code == 200:
            self._fixed_ip_cache[mac] = [fixed_ip['_ref'] for fixed_ip in r.json()]
        return (r.json(), r.status_code)

    def delete_fixed_ip(self, mac: str = '', ref: str = '') -> dict:
        deleted_fiex_ips = {}
        if mac:
            try:
                fixed_ip_data = self._fixed_ip_cache[mac]
            except KeyError:
                fixed_ip_data, status_code = self.get_fixed_ip(mac=mac)

            for fixed_ip in fixed_ip_data:
                ip = fixed_ip['_ref'].split(':')[1].split('/')[0]
                deleted_fiex_ips[ip] = self._delete_fixed_ip(ref=ref)
        elif ref:
            ip = ref.split(':')[1].split('/')[0]
            deleted_fiex_ips[ip] = self._delete_fixed_ip(ref=ref)

        return deleted_fiex_ips

    def create_fix_ip(self, ip: str, mac: str, name: str, comment: str) -> requests:
        r = requests.post(f'{self._base_url}fixedaddress?mac={mac}&ipv4addr={ip}&name={name}&comment={comment}',
                          **self._settings)

        return r

    def get_ip_info(self, ip: str) -> dict:
        r = requests.get(f'{self._base_url}ipv4address?ip_address={ip}', **self._settings)
        data = r.json()
        if r.status_code == 200 and data:
            return data
        else:
            return {}

    def get_all_networks(self, max_results: int=20000, return_fiedls: str='network,netmask,ipv4addr,options') -> dict:
        r = requests.get(f'{self._base_url}network?_max_results={max_results}&_return_fields={return_fiedls}',
                         **self._settings)
        data = r.json()
        if r.status_code == 200 and data:
            return data
        else:
            return {}
