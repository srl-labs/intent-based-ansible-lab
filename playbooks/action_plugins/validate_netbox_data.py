from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from ansible import constants as C
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import missing_required_lib
import traceback
from collections import namedtuple


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
            display.vvvv("Devices:\n%s" % ("\n".join([f"- {x.name}" for x in devices]),))

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
            display.vvvv("L2VPN tags:\n%s" % ("\n".join([f"- {x.name}" for x in l2vpn_svc_tags]),))

            svc_tenants = {tenant for tenant in nb.tenancy.tenants.all() if tenant.name[:4] == "svc:"}
            display.vvvv("Service tenants:\n%s" % ("\n".join([f"- {x.name}" for x in svc_tenants]),))

            l2vpns = list(l2vpn_ep.all())
            vrfs = list(nb.ipam.vrfs.all())
            ifaces = list(nb.dcim.interfaces.all())

            l2vpn_by_names = dict()  # Stores a mapping between L2VPN names and L2VPN objects
            l2vpn_by_ids = dict()  # Stores a mapping between L2VPN ids and L2VPN objects
            l2vpn_ids_for_endpoints = set()  # Stores ids of L2VPNs encountered on (relevant!) endpoints via 'l2vpn:<name>' tags
            l2vpn_endpoints_by_ids = dict()  # Stores a mapping between L2VPN ids and a list of (device, interface, ) objects tuples where they were found

            vrf_by_ids = dict()  # Stores a mapping vetween VRF ids and VRF objects
            vrf_ids_for_endpoints = set()  # Stores ids of VRFs encountered on (relevant!) endpoints via L2VPN objects linking to them
            vrf_l2vpns_by_ids = dict()  # Stores a mapping between VRF ids and the set of L2VPN ids where they were found
            wanvrf_vrfs_by_ids = dict()  # Stores a mapping between VRF ids (used as WANVRF) and the set of VRF ids where they were found
            vrf_having_wanvrf = set()  # Stores ids of VRFs that uses a WANVRF

            Tenant_objects = namedtuple('Tenant_objects', ['l2vpns', 'vrfs'])
            svctenant_objects_by_ids = dict()
            svctenant_ids_for_endpoints = set()  # Stores ids of tenants encountered on (relevant!) endpoints via L2VPNs or VRFs

            lags = set()
            lags_by_names = dict()
            lag_ifaces_by_ids = dict()

            for l2vpn in l2vpns:
                l2vpn_by_names[l2vpn.name] = l2vpn
                l2vpn_by_ids[l2vpn.id] = l2vpn
                l2vpn_endpoints_by_ids[l2vpn.id] = list()  # Initialize lists to be populated later

                if l2vpn.tenant:
                    if l2vpn.tenant.id not in svctenant_objects_by_ids:
                        svctenant_objects_by_ids[l2vpn.tenant.id] = Tenant_objects(set(), set())
                    svctenant_objects_by_ids[l2vpn.tenant.id].l2vpns.add(l2vpn)

                if l2vpn.custom_fields.get("L2vpn_ipvrf", None) and l2vpn.custom_fields.get("L2vpn_ipvrf").get("id", None):
                    vrfid = l2vpn.custom_fields.get("L2vpn_ipvrf").get("id")
                    if vrfid not in vrf_l2vpns_by_ids:
                        vrf_l2vpns_by_ids[vrfid] = set()
                    vrf_l2vpns_by_ids[vrfid].add(l2vpn.id)

            for vrf in vrfs:
                vrf_by_ids[vrf.id] = vrf

                if vrf.tenant:
                    if vrf.tenant.id not in svctenant_objects_by_ids:
                        svctenant_objects_by_ids[vrf.tenant.id] = Tenant_objects(set(), set())
                    svctenant_objects_by_ids[vrf.tenant.id].vrfs.add(vrf)

                if vrf.custom_fields.get("Vrf_wanvrf", None) and vrf.custom_fields.get("Vrf_wanvrf").get("id", None):
                    wanvrfid = vrf.custom_fields.get("Vrf_wanvrf").get("id")
                    if wanvrfid not in wanvrf_vrfs_by_ids:
                        wanvrf_vrfs_by_ids[wanvrfid] = set()
                    wanvrf_vrfs_by_ids[wanvrfid].add(vrf.id)
                    vrf_having_wanvrf.add(vrf.id)

            for iface in ifaces:
                if iface.lag and iface.device in devices:
                    lags.add(iface.lag)
                    if iface.lag.name not in lags_by_names:
                        lags_by_names[iface.lag.name] = set()
                    lags_by_names[iface.lag.name].add(iface.lag)
                    if iface.lag.id not in lag_ifaces_by_ids:
                        lag_ifaces_by_ids[iface.lag.id] = set()
                    lag_ifaces_by_ids[iface.lag.id].add(iface)

                for tag in iface.tags:
                    if tag in l2vpn_svc_tags:
                        if tag.name[6:] not in l2vpn_by_names:
                            tgt = validation_problems if iface.device in devices else validation_warnings
                            tgt.append(f"No L2VPN service with name `{tag.name[6:]}` found " +
                                       f"for interface `{iface.name}` of device `{iface.device.name}`.")
                        else:
                            svc = l2vpn_by_names[tag.name[6:]]
                            l2vpn_endpoints_by_ids[svc.id].append((iface.device, iface,))
                            if iface.device in devices:
                                display.vvvv(f"Device `{iface.device.name}` has tag `{tag.name}` on it's interface `{iface.name}`")
                                l2vpn_ids_for_endpoints.add(svc.id)

                                if l2vpn.tenant:
                                    svctenant_ids_for_endpoints.add(l2vpn.tenant.id)

                                if svc.custom_fields.get("L2vpn_ipvrf", None) and svc.custom_fields.get("L2vpn_ipvrf").get("id", None):
                                    vrf = vrf_by_ids[svc.custom_fields.get("L2vpn_ipvrf").get("id")]
                                    vrf_ids_for_endpoints.add(vrf.id)

                                    if vrf.tenant:
                                        svctenant_ids_for_endpoints.add(vrf.tenant.id)

                                    if vrf.custom_fields.get("Vrf_wanvrf", None) and vrf.custom_fields.get("Vrf_wanvrf").get("id", None):
                                        wanvrf = vrf_by_ids[vrf.custom_fields.get("Vrf_wanvrf").get("id")]
                                        vrf_ids_for_endpoints.add(wanvrf.id)

                                        if wanvrf.tenant:
                                            svctenant_ids_for_endpoints.add(wanvrf.tenant.id)

            display.vvvv(f"l2vpn map: {l2vpn_by_ids}")
            display.vvvv(f"vrf map: {vrf_by_ids}")
            display.vvvv(f"l2vpn_endpoints_by_ids: {l2vpn_endpoints_by_ids}")
            display.vvvv(f"l2vpn_ids_for_endpoints: {l2vpn_ids_for_endpoints}")
            display.vvvv(f"vrf_ids_for_endpoints: {vrf_ids_for_endpoints}")
            display.vvvv(f"vrf_l2vpns_by_ids: {vrf_l2vpns_by_ids}")
            display.vvvv(f"wanvrf_vrfs_by_ids: {wanvrf_vrfs_by_ids}")

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

            for lagname, lagifaces in lags_by_names.items():
                mh_ids = set()
                mh_modes = set()
                for lagiface in lagifaces:
                    if lagiface.custom_fields.get("Iface_mh_id", None) is None:
                        validation_problems.append(f"LAG interface `{lagiface.name}` on  `{lagiface.device.name}` has no value for `MH_ID`!")
                    else:
                        mh_ids.add(lagiface.custom_fields.get("Iface_mh_id"))

                    if lagiface.custom_fields.get("Iface_mh_mode", None) is None:
                        validation_problems.append(f"LAG interface `{lagiface.name}` on  `{lagiface.device.name}` has no value for `MH_mode`!")
                    else:
                        mh_modes.add(lagiface.custom_fields.get("Iface_mh_mode"))

                    if len(lag_ifaces_by_ids[lagiface.id]) == 0:
                        validation_problems.append(f"LAG interface `{lagiface.name}` on  `{lagiface.device.name}` has no child interfaces!")

                if len(mh_ids) != 1:
                    validation_problems.append(f"Not all LAG interface with name `{lagname}` share the same value for `MH_ID`!")

                if len(mh_modes) != 1:
                    validation_problems.append(f"Not all LAG interface with name `{lagname}` share the same value for `MH_mode`!")

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

            for vrfid in (vrf_l2vpns_by_ids.keys() & wanvrf_vrfs_by_ids.keys()):
                tgt = validation_problems if (vrf_by_ids[vrfid] in relevant_vrfs or
                                              any([l2vpn_by_ids[x] in relevant_l2vpns for x in vrf_l2vpns_by_ids[vrfid]])) else validation_warnings
                tgt.append(f"VRF `{vrf_by_ids[vrfid].name}` is both used as an L3VPN service by L2VPNs: " +
                           f"{['%s' % (l2vpn_by_ids[x].name, ) for x in vrf_l2vpns_by_ids[vrfid]]}" +
                           f"; and as a WANVRF service by VRFs: {['%s' % (vrf_by_ids[x].name, ) for x in wanvrf_vrfs_by_ids[vrfid]]}!")

            for vrfid in (vrf_having_wanvrf & wanvrf_vrfs_by_ids.keys()):
                tgt = validation_problems if (vrf_by_ids[vrfid] in relevant_vrfs or
                                              any([vrf_by_ids[x] in relevant_vrfs for x in wanvrf_vrfs_by_ids[vrfid]])) else validation_warnings
                tgt.append(f"VRF `{vrf_by_ids[vrfid].name}` is both used as a WAN-VRF service by VRFs: " +
                           f"{['%s' % (vrf_by_ids[x].name, ) for x in wanvrf_vrfs_by_ids[vrfid]]}" +
                           f"; and points to a WAN-VRF `{vrf_by_ids[vrfid].custom_fields.get('Vrf_wanvrf').get('name')}`!")

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

            for vrfid in (vrf_ids_for_endpoints & vrf_l2vpns_by_ids.keys()):  # Check VRF - L2VPN associations
                vrf = vrf_by_ids[vrfid]
                vrf_comm_state = vrf.custom_fields.get("Commissioning_state", None)
                vrf_loc = vrf.custom_fields.get('Service_location', None) or {}
                vrf_tenant = vrf.tenant.name if vrf.tenant else ''
                vrf_state = f"{vrf_comm_state or 'uncommissioned'} " if vrf_comm_state != "Commissioned" else ""

                for l2vpnid in vrf_l2vpns_by_ids[vrfid]:
                    l2vpn = l2vpn_by_ids[l2vpnid]
                    l2vpn_comm_state = l2vpn.custom_fields.get("Commissioning_state", None)
                    l2vpn_loc = l2vpn.custom_fields.get('Service_location', None) or {}
                    l2vpn_tenant = l2vpn.tenant.name if l2vpn.tenant else ''
                    l2vpn_state = f"{l2vpn_comm_state or 'uncommissioned'} " if l2vpn_comm_state != "Commissioned" else ""

                    # tgt = validation_problems if (vrf_comm_state == "Commissioned" or l2vpn_comm_state == "Commissioned") else validation_warnings
                    tgt = validation_problems if l2vpn_comm_state == "Commissioned" else validation_warnings

                    if l2vpn.tenant != vrf.tenant:
                        tgt.append(f"{str.capitalize(l2vpn_state)}L2VPN `{l2vpn.name}` has a different tenant (`{l2vpn_tenant}`) than " +
                                   f"{str.lower(vrf_state)}VRF `{vrf.name}` (`{vrf_tenant}`)!")
                    if vrf_comm_state != l2vpn_comm_state:
                        tgt.append(f"{str.capitalize(l2vpn_state)}L2VPN `{l2vpn.name}` references {str.lower(vrf_state)}VRF `{vrf.name}`!")
                    if vrf_loc.get("name", None) != l2vpn_loc.get("name", None):
                        tgt.append(f"{str.capitalize(l2vpn_state)}L2VPN `{l2vpn.name}` references {str.lower(vrf_state)}VRF `{vrf.name}`, " +
                                   f"but it has a different location `{vrf_loc.get('name', None)}`!")

            for wanvrfid in (vrf_ids_for_endpoints & wanvrf_vrfs_by_ids.keys()):  # Check VRF - WANVRF associations
                wanvrf = vrf_by_ids[wanvrfid]
                wanvrf_comm_state = wanvrf.custom_fields.get("Commissioning_state", None)
                wanvrf_loc = wanvrf.custom_fields.get('Service_location', None) or {}
                wanvrf_tenant = wanvrf.tenant.name if wanvrf.tenant else ''
                wanvrf_state = f"{wanvrf_comm_state or 'uncommissioned'} " if wanvrf_comm_state != "Commissioned" else ""

                for vrfid in wanvrf_vrfs_by_ids[wanvrfid]:
                    vrf = vrf_by_ids[vrfid]
                    vrf_comm_state = vrf.custom_fields.get("Commissioning_state", None)
                    vrf_loc = vrf.custom_fields.get('Service_location', None) or {}
                    vrf_tenant = vrf.tenant.name if vrf.tenant else ''
                    vrf_state = f"{vrf_comm_state or 'uncommissioned'} " if vrf_comm_state != "Commissioned" else ""

                    tgt = validation_problems if (wanvrf_comm_state == "Commissioned" or vrf_comm_state == "Commissioned") else validation_warnings

                    if vrf.tenant != wanvrf.tenant:
                        tgt.append(f"{str.capitalize(vrf_state)}VRF `{vrf.name}` has a different tenant (`{vrf_tenant}`) than " +
                                   f"{str.lower(wanvrf_state)}WAN-VRF `{wanvrf.name}` (`{wanvrf_tenant}`)!")
                    if wanvrf_comm_state != vrf_comm_state:
                        tgt.append(f"{str.capitalize(vrf_state)}VRF `{vrf.name}` references {str.lower(wanvrf_state)}WAN-VRF `{wanvrf.name}`!")
                    if wanvrf_loc.get("name", None) != vrf_loc.get("name", None):
                        tgt.append(f"{str.capitalize(vrf_state)}VRF `{vrf.name}` references {str.lower(wanvrf_state)}WAN-VRF `{wanvrf.name}`, " +
                                   f"but it has a different location `{wanvrf_loc.get('name', None)}`!")

            for svc_tenant in svc_tenants:
                if svc_tenant.id in svctenant_ids_for_endpoints:
                    wanvrf_export_targets = set()
                    wanvrf_import_targets = set()
                    connected_wanvrfs = {x for x in svctenant_objects_by_ids[svc_tenant.id].vrfs if x.id in wanvrf_vrfs_by_ids.keys()}
                    for wanvrf in connected_wanvrfs:
                        for rt in wanvrf.export_targets:
                            wanvrf_export_targets.add(rt)
                        for rt in wanvrf.import_targets:
                            wanvrf_import_targets.add(rt)

                    if len(wanvrf_export_targets) != 1:
                        validation_problems.append(f"Not all services for tenant `{svc_tenant.name}` use the same export route target!\n\t" +
                                                   str({x.name: [str(rt) for rt in x.export_targets] for x in connected_wanvrfs}))

                    if len(wanvrf_import_targets) != 1:
                        validation_problems.append(f"Not all services for tenant `{svc_tenant.name}` use the same import route target!\n\t" +
                                                   str({x.name: [str(rt) for rt in x.import_targets] for x in connected_wanvrfs}))

        except Exception as e:
            raise AnsibleError(f"{type(e).__name__} occured: {to_native(e)}" + "\n" + f"{traceback.format_exc()}")

        if len(validation_problems) > 0:
            display.display("Problems found:\n%s" % ("\n".join([f"- {x}" for x in validation_problems]),), color=C.COLOR_WARN)
            result["failed"] = True
            result["msg"] = f"There {'was' if len(validation_problems) == 1 else 'were'} {len(validation_problems)} validation " + \
                            f"problem{'' if len(validation_problems) == 1 else 's'} found!"

        if display.verbosity > 0 and len(validation_warnings) > 0:
            display.display("Warnings:\n%s" % ("\n".join([f"- {x}" for x in validation_warnings]),), color=C.COLOR_WARN)

        return result
