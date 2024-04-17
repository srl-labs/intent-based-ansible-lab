from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from ansible import constants as C
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import missing_required_lib
import traceback


display = Display()


try:
    import pynetbox
except ImportError as imp_exc:
    PYNETBOX_IMPORT_ERROR = imp_exc
else:
    PYNETBOX_IMPORT_ERROR = None


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

        if PYNETBOX_IMPORT_ERROR:
            result["failed"] = True
            result["msg"] = missing_required_lib("pynetbox")
            result["exception"] = PYNETBOX_IMPORT_ERROR
            return result

        if PACKAGING_IMPORT_ERROR:
            result["failed"] = True
            result["msg"] = missing_required_lib("packaging")
            result["exception"] = PACKAGING_IMPORT_ERROR
            return result

        if task_vars.get("netbox_discovered", None) is None:
            result["skipped"] = True
            result["msg"] = "The netbox discovery action plugin has not been run"
            return result
        elif not task_vars.get("netbox_discovered"):
            result["skipped"] = True
            result["msg"] = "The netbox discovery action plugin has not found Netbox"
            return result

        validation_problems = list()
        validation_warnings = list()

        try:
            nb = pynetbox.api(task_vars.get("netbox_url"), token=task_vars.get("netbox_token"))

            if version.parse(nb.version) < version.parse("3.7"):
                l2vpn_ep = nb.ipam.l2vpns
            else:
                if version.parse(pynetbox.__version__) < version.parse("7.3"):
                    raise RuntimeError(f"Netbox>=3.7 requires pynetbox>=7.3!\nYou have netbox=={nb.version} and pynetbox=={pynetbox.__version__}")
                l2vpn_ep = nb.vpn.l2vpns

            # Prepare device filters
            filters = {key: [di_val for di in task_vars.get("netbox_query_filters")
                       for di_key, di_val in di.items() if di_key == key]
                       for key in {x for item in task_vars.get("netbox_query_filters") for x in item.keys()}}
            if "role" not in filters:
                # Always include filter on role!
                filters["role"] = ['leaf', 'spine', 'borderleaf', 'superspine', 'dcgw']
            if "platform" not in filters:
                # Always include filter on platform!
                filters["platform"] = ['sros', 'srl']

            devices = list(nb.dcim.devices.filter(**filters))
            # display.display("Devices:\n%s" % ("\n".join([f"- {x.name}" for x in devices]),), color=C.COLOR_VERBOSE)

            if len(devices) == 0:
                raise AnsibleError("Unable to retrieve devices from netbox!")

            devnames_by_roles = {dev.role.name: [x.name for x in devices if x.role == dev.role] for dev in devices}

            groups = task_vars.get("groups", {})

            # Validate that the Ansible inventory devices match with the Netbox objects we retrieved.
            for devgroup in ['leaf', 'spine', 'borderleaf', 'superspine', 'dcgw']:
                if set(devnames_by_roles.get(devgroup, [])) != set(groups.get(devgroup, [])):
                    raise AnsibleError(f"Inventory/device mismatch with netbox for {devgroup}!")

            # Validate that all devices have the same location.
            if len({x.location for x in devices}) != 1:
                raise AnsibleError("Not all devices have the same location!")
            location = devices[0].location

            l2vpn_svc_tags = {tag for tag in nb.extras.tags.all() if tag.name[:6] == "l2vpn:"}
            l2vpns = list(l2vpn_ep.all())
            l2vpn_by_names = {x.name: x for x in l2vpns}
            l2vpn_by_ids = {x.id: x for x in l2vpns}
            display.vvvv(f"l2vpn map: {l2vpn_by_ids}")

            # Validate from device interface perspective
            l2vpn_ids_for_endpoints = set()
            l2vpn_endpoints_by_ids = {x.id: [] for x in l2vpns}
            for dev in devices:
                for iface in nb.dcim.interfaces.filter(device_id=dev.id):
                    for tag in iface.tags:
                        if tag in l2vpn_svc_tags:
                            display.vvvv(f"Device {dev.name} has tag {tag} on it's interface {iface.name}")
                            if tag.name[6:] not in l2vpn_by_names:
                                validation_problems.append(f"No L2VPN service with name `{tag.name[6:]}` found " +
                                                           f"for interface `{iface.name}` of device `{dev.name}`.")
                            else:
                                svcid = l2vpn_by_names[tag.name[6:]].id
                                l2vpn_ids_for_endpoints.add(svcid)
                                l2vpn_endpoints_by_ids[svcid].append((dev, iface,))
            display.vvvv(f"l2vpn_ids_for_endpoints: {l2vpn_ids_for_endpoints}")
            display.vvvv(f"l2vpn_endpoints_by_ids: {l2vpn_endpoints_by_ids}")

            l2vpn_ids_for_location = {x.id for x in l2vpns
                                      if x.custom_fields.get("Service_location", None) and
                                      x.custom_fields.get("Service_location").get("id", None) == location.id}
            display.vvvv(f"l2vpn_ids_for_location: {l2vpn_ids_for_location}")

            l2vpn_ids_with_issues = (l2vpn_ids_for_location ^ l2vpn_ids_for_endpoints)

            relevant_l2vpns = [x for x in l2vpns if x.id in (l2vpn_ids_for_endpoints | l2vpn_ids_for_location)]
            display.vvvv(f"relevant_l2vpns: {relevant_l2vpns}")

            for svc in relevant_l2vpns:
                display.vvvv(f"SVC {svc.name} has Commissioning_state {svc.custom_fields.get('Commissioning_state', None)}")
                # Check commisioning field is set:
                if svc.custom_fields.get("Commissioning_state", None) is None:
                    validation_problems.append(f"Service `{svc.name}` has no value for `Commissioning_state`!")
                elif svc.custom_fields.get("Commissioning_state", None) == "Commissioned":
                    tgt = validation_problems
                    svcstring = "Service"
                else:
                    tgt = validation_warnings
                    svcstring = f"{svc.custom_fields.get('Commissioning_state', None)} service"

                if svc.custom_fields.get("L2vpn_vlan", None) is None:
                    tgt.append(f"{str.capitalize(svcstring)} `{svc.name}` has no value for `802.1Q`!")
                if svc.custom_fields.get("Service_location", None) is None:
                    tgt.append(f"{str.capitalize(svcstring)} `{svc.name}` has no value for `Location`!")
                if svc.identifier is None:
                    tgt.append(f"{str.capitalize(svcstring)} `{svc.name}` has no value for `Identifier`!")
                if len(svc.export_targets) != 1:
                    tgt.append(f"{str.capitalize(svcstring)} `{svc.name}` should have exactly 1 `Export targets`, but has {len(svc.export_targets)}!")
                if len(svc.import_targets) != 1:
                    tgt.append(f"{str.capitalize(svcstring)} `{svc.name}` should have exactly 1 `Import targets`, but has {len(svc.import_targets)}!")
                if (svc.custom_fields.get("L2vpn_ipvrf", None) is None) ^ (svc.custom_fields.get("L2vpn_gateway", None) is None):
                    tgt.append(f"{str.capitalize(svcstring)} `{svc.name}` should have both or none of `IP-VRF` and `Gateway` filled in!")
                if svc.custom_fields.get("L2vpn_ipvrf", None) is not None:
                    # TODO: tenant check and VRF check
                    pass
                if svc.id in l2vpn_ids_with_issues:
                    if svc.id in l2vpn_ids_for_location:
                        tgt.append(f"{str.capitalize(svcstring)} `{svc.name}` is defined for location `{location.name}`, " +
                                   f"but has no device-interfaces associated with it via tag `l2vpn:{svc.name}`")
                    else:
                        svcloc = svc.custom_fields.get('Service_location', None) or {}
                        for ep in l2vpn_endpoints_by_ids[svc.id]:
                            tgt.append(f"{str.capitalize(svcstring)} `{svc.name}` is defined on iterface `{ep[1].name}` of device `{ep[0].name}`, " +
                                       f"but it has a different location `{svcloc.get('name', None)}`.")

        except Exception as e:
            raise AnsibleError(f"{type(e).__name__} occured: {to_native(e)}" + "\n" + f"{traceback.format_exc()}")

        if len(validation_problems) > 0:
            display.display("Problems found:\n%s" % ("\n".join([f"- {x}" for x in validation_problems]),), color=C.COLOR_WARN)
            result["failed"] = True
            result["msg"] = f"There {'was' if len(validation_problems) == 1 else 'were'} {len(validation_problems)} validation " + \
                            f"problem{'' if len(validation_problems) == 1 else 's'} found!"

        if len(validation_warnings) > 0:
            display.display("Warnings:\n%s" % ("\n".join([f"- {x}" for x in validation_warnings]),), color=C.COLOR_WARN)

        return result
