from ansible.plugins.action import ActionBase
from ansible.parsing.dataloader import DataLoader
from ansible.inventory.data import InventoryData
from ansible.module_utils._text import to_bytes
from ansible.inventory.manager import IGNORED
from ansible.plugins.loader import inventory_loader
from ansible.utils.display import Display
from ansible.module_utils.ansible_release import __version__ as ansible_version
from ansible.module_utils.urls import open_url
from ansible.utils import py3compat
from ansible.module_utils.basic import missing_required_lib
import re
import os


display = Display()


try:
    from packaging import version
except ImportError as imp_exc:
    PACKAGING_IMPORT_ERROR = imp_exc
else:
    PACKAGING_IMPORT_ERROR = None


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}

        result = super().run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        if PACKAGING_IMPORT_ERROR:
            result["failed"] = True
            result["msg"] = missing_required_lib("packaging")
            result["exception"] = PACKAGING_IMPORT_ERROR
            return result

        discovery_result = dict()
        discovery_result["netbox_discovered"] = False

        def _expand_inventory_sources(sources, expanded_sources=None):
            if expanded_sources is None:
                expanded_sources = list()

            for src in sources:
                if os.path.isdir(src):
                    _expand_inventory_sources([os.path.join(src, x) for x in sorted(os.listdir(src)) if IGNORED.search(to_bytes(x)) is None], expanded_sources)
                else:
                    expanded_sources.append(src)

            return expanded_sources

        inventory_sources = _expand_inventory_sources(task_vars.get("ansible_inventory_sources", []))
        _inventory = InventoryData()
        _loader = DataLoader()

        try:
            nb_plugin = inventory_loader.get("netbox.netbox.nb_inventory")
            nb_plugin.headers = {}  # Initialize header field normally initialized by parse()

            if not hasattr(type(nb_plugin), "_set_authorization"):  # Introduced in v3.14.0, if we have an older NBplugin, patch class with compatible code
                def _set_authorization(self):
                    # NetBox access
                    if version.parse(ansible_version) < version.parse("2.11"):
                        token = self.get_option("token")
                    else:
                        self.templar.available_variables = self._vars
                        token = self.templar.template(
                            self.get_option("token"), fail_on_undefined=False
                        )
                    if token:
                        self.headers.update({"Authorization": "Token %s" % token})
                type(nb_plugin)._set_authorization = _set_authorization

            for src in inventory_sources:
                display.v(f"Testing inventory source '{src}'")

                super(type(nb_plugin), nb_plugin).parse(_inventory, _loader, src, cache=False)

                plugin_wants = False
                try:
                    plugin_wants = bool(nb_plugin.verify_file(src))

                    if plugin_wants:
                        _ = nb_plugin._read_config_data(src)
                        display.v(f"Inventory source '{src}' is a netbox inventory config!")
                        nb_plugin._set_authorization()  # Updates the header field with authorization headers if present
                        url = nb_plugin.get_option("api_endpoint").strip("/")
                        token = nb_plugin.get_option("token")
                        headers = nb_plugin.headers
                        if version.parse(ansible_version) < version.parse("2.11"):
                            filters = nb_plugin.get_option("query_filters")
                            filters.extend(nb_plugin.get_option("device_query_filters"))
                        else:
                            filters = nb_plugin.templar.template(nb_plugin.get_option("query_filters"))
                            filters.extend(nb_plugin.templar.template(nb_plugin.get_option("device_query_filters")))
                        display.v(f"Filters: {filters}")

                        _ = open_url(f"{url}/api/status/", headers=headers)
                        display.v(f"Yes! We've succesfully made contact with netbox at '{url}'!")
                        discovery_result["netbox_discovered"] = True
                        discovery_result["netbox_url"] = url
                        discovery_result["netbox_token"] = token
                        discovery_result["netbox_authorization_headers"] = headers
                        discovery_result["netbox_query_filters"] = filters
                        discovery_result["netbox_query_filter_str"] = " ".join([f"{key}={value}" for item in filters for key, value in item.items()])
                        break

                    else:
                        display.v(f"Nope... Inventory source '{src}' is not a netbox inventory config")

                except Exception as e:
                    display.v(f"Nope... No netbox in inventory source '{src}'")
                    display.vvvv(f"{e}")

        except Exception as e:
            display.v(f"Nb_inventory plugin could not be loaded!\n{e}")

        if not discovery_result["netbox_discovered"]:
            # We could add code here to look for Ansible variables or Environment variables that has name that suggests it could be Netbox information
            # using regex; and also verify the provided data using regex to be valid...
            nb_variable_name_re = re.compile(r'(<=[^a-z]|^)n(?:et)?b(?:ox)?(?=[^a-z]|$)', re.I)
            url_variable_name_re = re.compile(r'api|addr(?:ess)?|url|endpoint', re.I)
            token_variable_name_re = re.compile(r'token|key', re.I)
            tenant_variable_name_re = re.compile(r'tenant', re.I)
            url_re = re.compile(r'^https?://', re.I)
            token_re = re.compile(r'^[a-fA-F0-9]{40}$')
            tenant_re = re.compile(r'^[a-fA-F0-9_-]+$')

            env_vars = {var: py3compat.environ[var] for var in py3compat.environ.keys() if nb_variable_name_re.search(var)}
            display.vvv(f"Potential netbox environment variables are: {env_vars}")

            ansible_vars = {var: task_vars[var] for var in task_vars.keys() if nb_variable_name_re.search(var)}
            display.vvv(f"Potential netbox ansible variables are: {ansible_vars}")

            url = None
            token = None
            headers = None
            filters = []

            for d in [ansible_vars, env_vars]:
                for var, val in d.items():
                    if url_variable_name_re.search(var) and url_re.search(val):
                        url = val.strip("/")
                    if token_variable_name_re.search(var) and token_re.search(val):
                        token = val
                        headers = {"Authorization": "Token %s" % token}
                    if tenant_variable_name_re.search(var) and tenant_re.search(val):
                        filters = [{"tenant": val}]

            if token and url:
                display.v("Netbox discovered through variables...")
                try:
                    _ = open_url(f"{url}/api/status/", headers=headers)
                    display.v(f"Yes! We've succesfully made contact with netbox at '{url}'!")
                    discovery_result["netbox_discovered"] = True
                    discovery_result["netbox_url"] = url
                    discovery_result["netbox_token"] = token
                    discovery_result["netbox_authorization_headers"] = headers
                    discovery_result["netbox_query_filters"] = filters
                    discovery_result["netbox_query_filter_str"] = " ".join([f"{key}={value}" for item in filters for key, value in item.items()])
                except Exception as e:
                    display.v("Nope... Not able to reach netbox discovered through variables.")
                    display.vvvv(f"{e}")
                    pass
            else:
                display.v("No Netbox discovered through variables...")

        result.update(discovery_result)
        result["ansible_facts"] = discovery_result

        return result
