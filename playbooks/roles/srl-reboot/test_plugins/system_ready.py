from ansible.errors import AnsibleFilterError, AnsibleUndefinedVariable
from ansible.template import AnsibleUndefined
from ansible import constants as C
from ansible.module_utils.common.text.converters import to_native
from ansible.utils.display import Display
import re
import traceback

display = Display()
strip_yang_module = re.compile(r"^srl_nokia-[^:]+:")


def config_strip_modules(cfg):
    if isinstance(cfg, list):
        return [config_strip_modules(x) for x in cfg]
    elif isinstance(cfg, dict):
        return {config_strip_modules(k): config_strip_modules(v) for k, v in cfg.items()}
    elif isinstance(cfg, str):
        return strip_yang_module.sub("", cfg)
    else:
        return cfg


def verify_state_arg(state):
    if isinstance(state, AnsibleUndefined):
        raise AnsibleUndefinedVariable
    msg = "State is supposed to be the result of " + \
          "`nokia.srlinux.get(paths=[{path: '/platform', datastore: 'state'}, {path: '/network-instance[name=default]', datastore: 'state'}])`"
    if not isinstance(state, list):
        raise AttributeError(f"Wrong type, expected <list> instead of <{type(state).__name__}>\n{msg}")
    if not len(state) == 2:
        raise AttributeError(f"Wrong number of elements in state: {len(state)} instead of 2.\n{msg}")
    expectedstate0keys = {'linecard', 'control', 'chassis'}
    state0keys = {config_strip_modules(x) for x in state[0].keys()}
    if not expectedstate0keys.issubset(state0keys):
        raise AttributeError(f"First element of state does not look like '/platform' state info.\n{msg}")
    if len(state[1]) != 0:
        expectedstate1keys = {'admin-state', 'oper-state', 'protocols', 'type'}
        state1keys = {config_strip_modules(x) for x in state[1].keys()}
        if not expectedstate1keys.issubset(state1keys):
            raise AttributeError(f"Second element of state does not look like '/network-instance[name=default]' info.\n{msg}")
        if strip_yang_module.sub("", state[1]["type"]) != "default":
            raise AttributeError(f"Second element of state does not look like '/network-instance[name=default]' info.\n{msg}")


def list_to_dict(lst, key):
    return {x[key]: {k: v for k, v in x.items() if k != key} for x in lst}


def system_ready(state, prev_state=None):
    problems = list()
    try:
        try:
            verify_state_arg(state)
            state = config_strip_modules(state)
        except AttributeError:
            problems.append("Invalid state data")
            display.vvv(f"state: {traceback.format_exc()}")
        except AnsibleUndefinedVariable:
            problems.append("Unable to get state data")
            display.vvv(f"state: {traceback.format_exc()}")

        if prev_state is not None:
            try:
                verify_state_arg(prev_state)
                prev_state = config_strip_modules(prev_state)
            except AttributeError:
                problems.append("Invalid previous state data")
                display.vvv(f"prev_state: {traceback.format_exc()}")

        if len(problems) != 0:
            display.display("System is not ready because:\n%s" % ("\n".join([f"- {x}" for x in problems]),), color=C.COLOR_VERBOSE)
            return False

        if "sim serial" in str(state[0]["chassis"]["serial-number"]).lower():
            problems.append("Platform is not real hardware")

        if state[0]["chassis"]["oper-state"] != "up":
            problems.append(f"Platform is in `{state[0]['chassis']['oper-state']}` state instead of `up`")

        for control in state[0]["control"]:
            if control["oper-state"] != "up":
                problems.append(f"CPM in slot {control['slot']} is in `{control['oper-state']}` state instead of `up`")

        for linecard in state[0]["linecard"]:
            if linecard["oper-state"] != "up":
                problems.append(f"Linecard in slot {linecard['slot']} is in `{linecard['oper-state']}` state instead of `up`")

        if len(state[1]) > 0:
            if state[1]["admin-state"] == "enable" and state[1]["oper-state"] != "up":
                problems.append(f"Network instance default is in `{state[1]['oper-state']}` state instead of `up`")

            for protocol in state[1]["protocols"]:
                if "admin-state" in state[1]["protocols"][protocol] and state[1]["protocols"][protocol]["admin-state"] != "enable":
                    continue

                if "oper-state" in state[1]["protocols"][protocol] and state[1]["protocols"][protocol]["oper-state"] != "up":
                    problems.append(f"Protocol {protocol} of the default network instance is in `{state[1]['protocols'][protocol]['oper-state']}` state instead of `up`")

                if protocol == "bgp":
                    if prev_state is not None and "bgp" in prev_state[1]["protocols"]:
                        prev_neighbors = {k: v for k, v in list_to_dict(prev_state[1]["protocols"]["bgp"]["neighbor"], "peer-address").items() if v["admin-state"] == "enable"}
                    else:
                        prev_neighbors = {}

                    prev_peers = set(prev_neighbors.keys())
                    curr_peers = {x["peer-address"] for x in state[1]["protocols"]["bgp"]["neighbor"] if x["admin-state"] == "enable"}
                    if not prev_peers.issubset(curr_peers):
                        problems.append(f"The default network instance has missing BGP neighbors: {prev_peers - curr_peers}")

                    neighbors = list_to_dict(state[1]["protocols"]["bgp"]["neighbor"], "peer-address")
                    for peer in neighbors:
                        neighbor = neighbors[peer]
                        if neighbor["admin-state"] != "enable":
                            continue

                        if neighbor["session-state"] != "established":
                            problems.append(f"BGP neighbor {peer} of the default network instance is in `{neighbor['session-state']}` state instead of `established`")

                        afisafis = list_to_dict(neighbor["afi-safi"], "afi-safi-name")
                        if peer in prev_neighbors:
                            prev_afisafis = list_to_dict(prev_neighbors[peer]["afi-safi"], "afi-safi-name")
                        for afisafiname in afisafis:
                            afisafi = afisafis[afisafiname]
                            if afisafi["admin-state"] != "enable":
                                continue

                            if afisafi["oper-state"] != "up":
                                problems.append(f"BGP neighbor {peer} of the default network instance has afi-safi {afisafiname} in `{afisafi['oper-state']}` state instead of `up`")

                            if peer in prev_neighbors and afisafi["sent-routes"] == 0 and prev_afisafis[afisafiname]["sent-routes"] > 0:
                                problems.append(f"BGP neighbor {peer} of the default network instance has 0 {afisafiname} routes sent, but previously had {prev_afisafis[afisafiname]['sent-routes']}")

                            if peer in prev_neighbors and afisafi["received-routes"] == 0 and prev_afisafis[afisafiname]["received-routes"] > 0:
                                problems.append(f"BGP neighbor {peer} of the default network instance has 0 {afisafiname} routes received, but previously had {prev_afisafis[afisafiname]['received-routes']}")
        else:
            if prev_state is not None and len(prev_state[1]) > 0:
                problems.append("The default network instance is missing!")

    except Exception as e:
        raise AnsibleFilterError(f"{type(e).__name__} occured: {to_native(e)}" + "\n" + f"{traceback.format_exc()}")

    if len(problems) != 0:
        display.display("System is not ready because:\n%s" % ("\n".join([f"- {x}" for x in problems]),), color=C.COLOR_VERBOSE)
        return False
    return True


class TestModule(object):
    def tests(self):
        return {
            'system_ready': system_ready,
        }
