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

            vrfs = list(nb.ipam.vrfs.all())
            vrf_by_ids = {x.id: x for x in vrfs}
            display.vvvv(f"vrf map: {vrf_by_ids}")

            # Validate from device interface perspective
            l2vpn_ids_for_endpoints = set()
            l2vpn_endpoints_by_ids = {x.id: [] for x in l2vpns}

            vrf_ids_for_endpoints = set()
            vrf_l2vpns_by_ids = {x.id: set() for x in vrfs}

            for dev in devices:
                for iface in nb.dcim.interfaces.filter(device_id=dev.id):
                    for tag in iface.tags:
                        if tag in l2vpn_svc_tags:
                            display.vvvv(f"Device {dev.name} has tag {tag} on it's interface {iface.name}")
                            if tag.name[6:] not in l2vpn_by_names:
                                validation_problems.append(f"No L2VPN service with name `{tag.name[6:]}` found " +
                                                           f"for interface `{iface.name}` of device `{dev.name}`.")
                            else:
                                svc = l2vpn_by_names[tag.name[6:]]
                                l2vpn_ids_for_endpoints.add(svc.id)
                                l2vpn_endpoints_by_ids[svc.id].append((dev, iface,))

                                if svc.custom_fields.get("L2vpn_ipvrf", None) is not None:
                                    vrf_id = svc.custom_fields.get("L2vpn_ipvrf").get("id", None)
                                    vrf_ids_for_endpoints.add(vrf_id)
                                    vrf_l2vpns_by_ids[vrf_id].add(svc.id)

            display.vvvv(f"l2vpn_ids_for_endpoints: {l2vpn_ids_for_endpoints}")
            display.vvvv(f"l2vpn_endpoints_by_ids: {l2vpn_endpoints_by_ids}")

            display.vvvv(f"vrf_ids_for_endpoints: {vrf_ids_for_endpoints}")
            display.vvvv(f"vrf_l2vpns_by_ids: {vrf_l2vpns_by_ids}")

            l2vpn_ids_for_location = {x.id for x in l2vpns
                                      if x.custom_fields.get("Service_location", None) and
                                      x.custom_fields.get("Service_location").get("id", None) == location.id}
            display.vvvv(f"l2vpn_ids_for_location: {l2vpn_ids_for_location}")
            l2vpn_ids_with_issues = (l2vpn_ids_for_location ^ l2vpn_ids_for_endpoints)

            vrf_ids_for_location = {x.id for x in vrfs
                                    if x.custom_fields.get("Service_location", None) and
                                    x.custom_fields.get("Service_location").get("id", None) == location.id}
            display.vvvv(f"vrf_ids_for_location: {vrf_ids_for_location}")
            vrf_ids_with_issues = (vrf_ids_for_location ^ vrf_ids_for_endpoints)

            relevant_l2vpns = [x for x in l2vpns if x.id in (l2vpn_ids_for_endpoints | l2vpn_ids_for_location)]
            display.vvvv(f"relevant_l2vpns: {relevant_l2vpns}")

            relevant_vrfs = [x for x in vrfs if x.id in (vrf_ids_for_endpoints | vrf_ids_for_location)]
            display.vvvv(f"relevant_vrfs: {relevant_vrfs}")

            for svc in relevant_l2vpns:
                svc_comm_state = svc.custom_fields.get("Commissioning_state", None)
                display.vvvv(f"L2VPN {svc.name} has Commissioning_state {svc_comm_state}")
                # Check commisioning field is set:
                if svc_comm_state is None:
                    validation_problems.append(f"L2VPN `{svc.name}` has no value for `Commissioning_state`!")
                svcstring = "L2VPN" if svc_comm_state == "Commissioned" else f"{str.capitalize(svc_comm_state or 'uncommissioned')} L2VPN"
                tgt = validation_problems if svc_comm_state == "Commissioned" else validation_warnings

                if svc.custom_fields.get("L2vpn_vlan", None) is None:
                    tgt.append(f"{svcstring} `{svc.name}` has no value for `802.1Q`!")
                if svc.custom_fields.get("Service_location", None) is None:
                    tgt.append(f"{svcstring} `{svc.name}` has no value for `Location`!")
                if svc.identifier is None:
                    tgt.append(f"{svcstring} `{svc.name}` has no value for `Identifier`!")
                if len(svc.export_targets) != 1:
                    tgt.append(f"{svcstring} `{svc.name}` should have exactly 1 `Export targets`, but has {len(svc.export_targets)}!")
                if len(svc.import_targets) != 1:
                    tgt.append(f"{svcstring} `{svc.name}` should have exactly 1 `Import targets`, but has {len(svc.import_targets)}!")
                if (svc.custom_fields.get("L2vpn_ipvrf", None) is None) ^ (svc.custom_fields.get("L2vpn_gateway", None) is None):
                    tgt.append(f"{svcstring} `{svc.name}` should have both or none of `IP-VRF` and `Gateway` filled in!")
                if svc.id in l2vpn_ids_with_issues:
                    if svc.id in l2vpn_ids_for_location:
                        tgt.append(f"{svcstring} `{svc.name}` is defined for location `{location.name}`, " +
                                   f"but has no device-interfaces associated with it via tag `l2vpn:{svc.name}`!")
                    else:
                        svc_loc = svc.custom_fields.get('Service_location', None) or {}
                        for ep in l2vpn_endpoints_by_ids[svc.id]:
                            tgt.append(f"{svcstring} `{svc.name}` is defined on iterface `{ep[1].name}` of device `{ep[0].name}`, " +
                                       f"but it has a different location `{svc_loc.get('name', None)}`!")

            for svc in relevant_vrfs:
                svc_comm_state = svc.custom_fields.get("Commissioning_state", None)
                display.vvvv(f"VRF {svc.name} has Commissioning_state {svc_comm_state}")
                # Check commisioning field is set:
                if svc_comm_state is None:
                    validation_problems.append(f"VRF `{svc.name}` has no value for `Commissioning_state`!")
                svcstring = "VRF" if svc_comm_state == "Commissioned" else f"{str.capitalize(svc_comm_state or 'uncommissioned')} VRF"
                tgt = validation_problems if svc_comm_state == "Commissioned" else validation_warnings

                if svc.custom_fields.get("Vrf_identifier", None) is None:
                    tgt.append(f"{svcstring} `{svc.name}` has no value for `Identifier`!")
                if svc.custom_fields.get("Service_location", None) is None:
                    tgt.append(f"{svcstring} `{svc.name}` has no value for `Location`!")
                if len(svc.export_targets) != 1:
                    tgt.append(f"{svcstring} `{svc.name}` should have exactly 1 `Export targets`, but has {len(svc.export_targets)}!")
                if len(svc.import_targets) != 1:
                    tgt.append(f"{svcstring} `{svc.name}` should have exactly 1 `Import targets`, but has {len(svc.import_targets)}!")
                if svc.id in vrf_ids_with_issues:
                    if svc.id in vrf_ids_for_location:
                        tgt.append(f"{svcstring} `{svc.name}` is defined for location `{location.name}`, " +
                                   "but is not associated with any L2VPN service!")
                    else:
                        svc_loc = svc.custom_fields.get('Service_location', None) or {}
                        for l2vpn_id in vrf_l2vpns_by_ids[svc.id]:
                            tgt.append(f"{svcstring} `{svc.name}` is referenced in L2VPN `{l2vpn_by_ids[l2vpn_id]}`, " +
                                       f"but it has a different location `{svc_loc.get('name', None)}`!")
                # TODO: WANVRF stuff

            for vrfid in vrf_ids_for_endpoints:
                vrf = vrf_by_ids[vrfid]
                vrf_comm_state = vrf.custom_fields.get("Commissioning_state", None)
                vrf_loc = vrf.custom_fields.get('Service_location', None) or {}

                for l2vpnid in vrf_l2vpns_by_ids[vrfid]:
                    l2vpn = l2vpn_by_ids[l2vpnid]
                    l2vpn_comm_state = l2vpn.custom_fields.get("Commissioning_state", None)
                    l2vpnsvcstring = "L2VPN" if l2vpn_comm_state == "Commissioned" else f"{str.capitalize(l2vpn_comm_state or 'uncommissioned')} L2VPN"
                    tgt = validation_problems if l2vpn_comm_state == "Commissioned" else validation_warnings
                    l2vpn_loc = l2vpn.custom_fields.get('Service_location', None) or {}
                    if vrf_comm_state != l2vpn_comm_state:
                        tgt.append(f"{l2vpnsvcstring} `{l2vpn.name}` references a {str.lower(vrf_comm_state)} VRF `{vrf.name}`!")
                    if vrf_loc.get("name", None) != l2vpn_loc.get("name", None):
                        tgt.append(f"{l2vpnsvcstring} `{l2vpn.name}` references VRF `{vrf.name}`, " +
                                   f"but it has a different location `{vrf_loc.get('name', None)}`!")

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
