from ansible.plugins.action import ActionBase
from ansible.module_utils.basic import missing_required_lib
import traceback
import re
import itertools
from copy import deepcopy

NX_IMP_ERR = None
try:
    import networkx as nx
    HAS_NX = True
except ImportError:
    HAS_NX = False
    NX_IMP_ERR = traceback.format_exc()

NETADDR_IMP_ERR = None
try:
    import netaddr
    HAS_NETADDR = True
except ImportError:
    HAS_NETADDR = False
    NETADDR_IMP_ERR = traceback.format_exc()


# helper function expanding ranges
def expand_range(inp, hint=None, max_digits=4):
    """
    This function expands strings with embedded ranges into a list of strings.
    The ranges are specified by <start><delimiter><stop> enclosed in square brackets.
    <delimiter> can be a minus sign (-) or 2 dots (..).
    <start> and <stop> must be integers with <start> less or equal to <stop>.

    When `hint` (a list of strings) is given, also the following applies:
    - only strings that expand to a string present in `hint` will be returned
    - each range, when expanded, will be tested with leading zeros up to `max_digits`

    example:
      expand_range('leaf[1-1]', hint=['leaf1', 'leaf001', 'leaf00001'], max_digits=4)
    will be expanded to:
      ['leaf1', 'leaf001']

    '[1-1]' wil be expanded to '1', '01', '001' and '0001', but only '1' and '001'
    produces a match in `hint`, '00001' is not a candidate because `max_digits` was 4

    example:
      expand_range('ethernet-[1-2]/[1-3]')
    will be expanded to:
      ['ethernet-1/1', 'ethernet-1/2', 'ethernet-1/3', 'ethernet-2/1', 'ethernet-2/2', 'ethernet-2/3']
    """
    ret = list()
    if hint is None:
        hint = list()
    r_re = re.compile(r"\[(?P<start>\d+)(-|\.\.)(?P<stop>\d+)\]")

    # This list will store for each range we encounter a list of possible substitution candidates
    rangematch_candidates = list()
    for r_match in r_re.finditer(inp):
        # Iterate over all the ranges found in the input string
        r_start = int(r_match["start"])
        r_end = int(r_match["stop"]) + 1
        if r_end <= r_start:
            raise Exception(f"Invalid range {r_match[0]}")
        candidates = list()
        for i in range(r_start, r_end):
            # Generate all candidate replacement strings for the range
            if len(hint) > 0:
                # If hints are given, for each integer in the range, generate all candidates with leading 0s up to max_digit
                for j in range(1, max_digits + 1):
                    fmtstr = "{:0%sd}" % j
                    formatted_candidate = fmtstr.format(i)
                    if formatted_candidate not in candidates:
                        candidates.append(formatted_candidate)
            else:
                # No hints, so the only candidate is the string version of the number in the range
                candidates.append(str(i))
        # Done processing the current range, store the list of substitution candidates for this range
        rangematch_candidates.append(candidates)
    # All ranges processed. Now make all possible combinations by carthesian product.
    range_combo = itertools.product(*rangematch_candidates)
    for combo in range_combo:
        # Combo is a tuple that contains 1 possible substitution candidate for each range encountered
        # Even if there were no ranges to expand at all, itertools.product(*[]) produces [()] so we are covered.
        res = inp
        for substitution_candidate in combo:
            # One by one, the range gets substituted by it's substitution candidate
            res = r_re.sub(substitution_candidate, res, 1)
        if len(hint) > 0:
            # If hints are given, only expansions that have a match in hint are kept.
            if res in hint:
                ret.append(res)
        else:
            ret.append(res)
    return ret


class IpFabricParser:
    def __init__(self, fabric_nodes, fabric_intent):
        if not isinstance(fabric_nodes, dict):
            raise AttributeError("Wrong type for fabric_nodes")
        for key in fabric_nodes.keys():
            if key not in ['spine', 'leaf', 'superspine', 'dcgw', 'borderleaf']:
                raise AttributeError("Wrong key in fabric_nodes")
        if not isinstance(fabric_intent, dict):
            raise AttributeError(f"Wrong type for fabric_intent; expected <dict>, got <{type(fabric_intent).__name__}>.")
        if set(fabric_intent.keys()) != {'fabric', 'sizing'}:
            raise AttributeError(f"Wrong data in fabric_intent; expected keys {{fabric, sizing}}, got {{{', '.join(fabric_intent.keys())}}}.")

        self._fabric_nodes = fabric_nodes
        self._fabric_data = deepcopy(fabric_intent['fabric'])
        self._sizing = deepcopy(fabric_intent['sizing'])
        self._spine_islports = dict()
        self._overrides = dict()
        self._parse_topo()

    @property
    def max_pod(self):
        return self._sizing['max_pod']

    @property
    def max_dcgw(self):
        return self._sizing['max_dcgw']

    @property
    def max_superspine(self):
        return self._sizing['max_superspine']

    @property
    def max_spine_in_pod(self):
        return self._sizing['max_spine_in_pod']

    @property
    def max_borderleaf_in_pod(self):
        return self._sizing['max_borderleaf_in_pod']

    @property
    def max_leaf_in_pod(self):
        return self._sizing['max_leaf_in_pod']

    @property
    def max_isl_per_spine(self):
        return self._sizing['max_isl_per_spine']

    @property
    def max_isl_per_dcgw(self):
        return self._sizing['max_isl_per_dcgw']

    @property
    def fabric_data(self):
        return deepcopy(self._fabric_data)

    @property
    def fabric_nodes(self):
        return deepcopy(self._fabric_nodes)

    @property
    def topo(self):
        return deepcopy(self._topo)

    @property
    def spine_count(self):
        return len(self._fabric_nodes["spine"]) if "spine" in self._fabric_nodes else 0

    @property
    def leaf_count(self):
        return len(self._fabric_nodes["leaf"]) if "leaf" in self._fabric_nodes else 0

    @property
    def superspine_count(self):
        return len(self._fabric_nodes["superspine"]) if "superspine" in self._fabric_nodes else 0

    @property
    def borderleaf_count(self):
        return len(self._fabric_nodes["borderleaf"]) if "borderleaf" in self._fabric_nodes else 0

    @property
    def dcgw_count(self):
        return len(self._fabric_nodes["dcgw"]) if "dcgw" in self._fabric_nodes else 0

    @property
    def spines(self):
        return deepcopy(self._fabric_nodes["spine"]) if "spine" in self._fabric_nodes else list()

    @property
    def leafs(self):
        return deepcopy(self._fabric_nodes["leaf"]) if "leaf" in self._fabric_nodes else list()

    @property
    def superspines(self):
        return deepcopy(self._fabric_nodes["superspine"]) if "superspine" in self._fabric_nodes else list()

    @property
    def borderleafs(self):
        return deepcopy(self._fabric_nodes["borderleaf"]) if "borderleaf" in self._fabric_nodes else list()

    @property
    def dcgws(self):
        return deepcopy(self._fabric_nodes["dcgw"]) if "dcgw" in self._fabric_nodes else list()

    @property
    def nodes(self):
        return self.dcgws + self.superspines + self.spines + self.borderleafs + self.leafs

    @property
    def processed_fabric(self):
        ret = dict()
        nodeproperties = self._topo.nodes(True)
        for node in self.nodes:
            ret[node] = dict()
            ret[node].update(nodeproperties[node])
            ret[node]["isls"] = dict()
            for n1, n2, key, properties in self._topo.edges([node], data=True, keys=True):
                peer = n2 if node == n1 else n2
                iface = properties[node]
                ret[node]["isls"][iface] = {k: v for k, v in properties.items() if k not in {n1, n2, "p2p_address"}}
                if not self._topo.graph["bgp_unnumbered"]:
                    ret[node]["isls"][iface]["peer"] = peer
                    ret[node]["isls"][iface]["p2p_address"] = properties["p2p_address"][node]
                    ret[node]["isls"][iface]["peer_p2p_address"] = properties["p2p_address"][peer]
        ret["fabric"] = deepcopy(self._topo.graph)
        return ret

    def _parse_topo(self):
        shortport_re = re.compile(r"^e?([\d]+)[-/]([\d]+)$")

        self._topo = nx.MultiGraph()
        self._topo.graph["overlay_asn"] = int(self._fabric_data["overlay_asn"])
        self._topo.graph["bgp_unnumbered"] = "bgp-unnumbered" in self._fabric_data and self._fabric_data["bgp-unnumbered"]
        self._topo.graph["pods"] = dict()

        # Populate network-graph with nodes fabric_nodes (from ansible inventory)
        for nodetype, nodelist in self._fabric_nodes.items():
            self._topo.add_nodes_from([(node, {"role": nodetype},) for node in nodelist])
        self._topo.graph["single-tier"] = len(self.leafs) == 2 and len(self.nodes) == 2

        # Parse overrides
        if 'overrides' in self._fabric_data:
            for entry in self._fabric_data['overrides']:
                for node in expand_range(entry, self.nodes):
                    if node not in self._overrides:
                        self._overrides[node] = dict()
                    for k, v in self._fabric_data['overrides'][entry].items():
                        if k in self._overrides[node]:
                            raise Exception(f"An override for {node}[{k}] was already provided elsewhere!")
                        else:
                            self._overrides[node][k] = v

        # Parse spine ISL port info
        if 'spine' in self._fabric_data:
            for entry in self._fabric_data['spine']:
                for node in expand_range(entry, self.spines):
                    isl_ports = self._fabric_data['spine'][entry]['isl-ports']
                    isl_port_list = list()
                    if isinstance(isl_ports, list):
                        for isl_port_entry in isl_ports:
                            isl_port_list.extend(expand_range(isl_port_entry))
                    else:
                        isl_port_list = expand_range(isl_ports)

                    # Validate for duplicates
                    if len(isl_port_list) != len(set(isl_port_list)):
                        raise Exception(f"Isl-port information for spine {node} contains duplicates!")

                    # Validate for duplicates
                    if len(isl_port_list) > self.max_isl_per_spine:
                        raise Exception(f"Isl-port information for spine {node} contains more ISL ports than max_isl_per_spine!")

                    self._spine_islports[node] = isl_port_list

        # Populate network-graph with links from ipfabric_data
        for entry in self._fabric_data["fabric_cabling"]:
            if not isinstance(entry, dict):
                raise AttributeError("Wrong datatype for entry in fabric_cabling")
            if "endpoints" not in entry or len(entry["endpoints"]) != 2:
                raise AttributeError("Wrong data in fabric_cabling")
            endpoints = {splt[0]: shortport_re.sub(r"ethernet-\g<1>/\g<2>", splt[1])
                         for splt in [str.split(x, ":") for x in entry["endpoints"]]
                         }
            properties = {k: v for k, v in entry.items() if k != "endpoints"}
            if any([node not in self._topo.nodes for node in endpoints.keys()]):
                raise AttributeError("Wrong data in fabric_cabling; node not found!")

            self._topo.add_edges_from([tuple(endpoints.keys())], **endpoints, **properties)

        # First pass through the network-graph nodes to add properties
        for node, properties in self._topo.nodes(True):
            # Add id property
            if node in self._overrides and 'id' in self._overrides[node]:
                nodeid = self._overrides[node]['id']
            else:
                nodeid = int(re.search(r"\d+$", node)[0])
            self._topo.nodes[node]["id"] = nodeid

            # Add other properties
            if node in self._overrides:
                for k, v in self._overrides[node].items():
                    if k not in {'id', 'asn', 'loopback'}:  # These are handeled separately
                        self._topo.nodes[node][k] = v

            # Validate all nodes are connected into the fabric
            if len(self._topo[node]) == 0:
                raise Exception(f"Node {node} not connected into the fabric!")

        # Second pass through the network-graph nodes to group spines and (border-)leafs into pods
        podid_allocation = 0
        for node, properties in self._topo.nodes(True):
            # From (border-)leafs, take one that has no pod info (yet).
            if properties['role'] not in ['leaf', 'borderleaf']:
                continue
            if 'podid' in properties:
                continue
            leafrole = self._topo.nodes(data='role')[node]

            # From that leaf, list all adjacent spines => spines of the pod.
            spines_in_pod = [neighbor for neighbor in self._topo[node] if self._topo.nodes(data='role')[neighbor] == "spine"]

            if len(spines_in_pod) == 0:
                if self._topo.graph["single-tier"]:
                    podid = 0
                else:
                    raise Exception(f"Leaf {node} not connected to a spine!")
            elif 'podid' in self._topo.nodes[spines_in_pod[0]]:
                podid = self._topo.nodes[spines_in_pod[0]]["podid"]
            else:
                podid = podid_allocation
                podid_allocation += 1

            if podid not in self._topo.graph["pods"]:
                self._topo.graph["pods"][podid] = dict()
                if not self._topo.graph["single-tier"]:
                    self._topo.graph["pods"][podid]["spine"] = spines_in_pod
                else:
                    self._topo.graph["pods"][podid]["spine"] = list()
                self._topo.graph["pods"][podid]["borderleaf"] = list()
                self._topo.graph["pods"][podid]["leaf"] = list()

            if not self._topo.graph["single-tier"]:
                # From that spine, list all adjacent leafs => leafs of the pod.
                leafs_in_pod = [neighbor for neighbor in self._topo[spines_in_pod[0]] if self._topo.nodes(data='role')[neighbor] == leafrole]
            else:
                leafs_in_pod = self.leafs
            self._topo.graph["pods"][podid][leafrole] = leafs_in_pod

            # Verify that all spines/leafs in the pod have same adjacent nodes to validate full mesh.
            # Add pod info to all leafs and spines
            if not self._topo.graph["single-tier"]:
                # Sanity check spine layer and set podid
                spineids = [nodeid for node, nodeid in self._topo.nodes(data="id") if node in spines_in_pod]
                podspineidoffset = min(spineids) - 1
                for spine in spines_in_pod:
                    if {neighbor for neighbor in self._topo[spine] if self._topo.nodes(data='role')[neighbor] == leafrole} != set(leafs_in_pod):
                        raise Exception("No full mesh!")
                    self._topo.nodes[spine]["podid"] = podid
                    self._topo.nodes[spine]["id"] -= podspineidoffset  # Make spines in the pod count from 1 again
                    if self.superspine_count > 0:
                        if len([neighbor for neighbor in self._topo[spine] if self._topo.nodes(data='role')[neighbor] == "superspine"]) == 0:
                            raise Exception(f"spine {node} has no connection to superspine layer")

            # Sanity check leaf layer and set podid
            leafids = [nodeid for node, nodeid in self._topo.nodes(data="id") if node in leafs_in_pod]
            podleafidoffset = min(leafids) - 1
            for leaf in leafs_in_pod:
                if not self._topo.graph["single-tier"]:
                    if {neighbor for neighbor in self._topo[leaf] if self._topo.nodes(data='role')[neighbor] == "spine"} != set(spines_in_pod):
                        raise Exception("No full mesh!")
                else:
                    if set(self._topo[leaf]) != set(leafs_in_pod).difference({leaf}):
                        raise Exception("Single tier not interconnected!")
                self._topo.nodes[leaf]["podid"] = podid
                self._topo.nodes[leaf]["id"] -= podleafidoffset  # Make leafs in the pod count from 1 again

        # Preparation for asn and loopback allocation
        allocated_asns = dict()
        allocated_loopbacks = list()
        overwrite_loopbacks = list()

        self._topo.graph['loopback'] = list()

        asn_r_re = re.compile(r"^(?P<start>\d+)(-|\.\.)(?P<end>\d+)$")

        asnpool_gen = itertools.chain(*[range(int(asn_r_re.match(x)['start']), int(asn_r_re.match(x)['end']) + 1)
                                        for x in (self._fabric_data['asn'] if isinstance(self._fabric_data['asn'], list) else [self._fabric_data['asn']])])
        # asnpool_gen is a generator, could be huge!
        # convert genrator into list to allocate asn from, initially 16 long (arbitrary), grows later
        asnpool = list(itertools.islice(asnpool_gen, 16))

        if 'loopback' in self._fabric_data and self._fabric_data['loopback'] is not None:
            self._topo.graph['loopback'].append(str(netaddr.IPNetwork(self._fabric_data['loopback'])))
            loopback_pool = netaddr.IPNetwork(self._fabric_data['loopback'])
        else:
            loopback_pool = []

        # Third pass through the network-graph nodes for validation and assignment of ASN and loopback-addresses
        for node, properties in self._topo.nodes(True):
            nodeid = properties['id'] - 1  # make 0 based!
            # Validations per role
            if properties['role'] == 'spine':
                # Verify all spines have been assigned a podid
                if 'podid' not in properties:
                    raise Exception(f"Not able to determine podid for {node}")

                # Verify max spines in pod
                if nodeid >= self.max_spine_in_pod:
                    raise Exception(f"Spine {node} exceeds maximum # spines in pod!")

                # When not using BGP unnumbered, validate that ISL ports are defined for spine
                if not self._topo.graph["bgp_unnumbered"] and node not in self._spine_islports:
                    raise Exception(f"No isl-port information found for spine {node}")
            elif properties['role'] == 'leaf':
                # Verify all leafs have been assigned a podid
                if 'podid' not in properties:
                    raise Exception(f"Not able to determine podid for {node}")

                # Verify max leafs in pod
                if nodeid >= self.max_leaf_in_pod:
                    raise Exception(f"Leaf {node} exceeds maximum # leafs in pod!")
            elif properties['role'] == 'borderleaf':
                # Verify all borderleafs have been assigned a podid
                if 'podid' not in properties:
                    raise Exception(f"Not able to determine podid for {node}")

                # Verify max borderleafs in pod
                if nodeid >= self.max_borderleaf_in_pod:
                    raise Exception(f"Borderleaf {node} exceeds maximum # borderleafs in pod!")
            elif properties['role'] == 'superspine':
                # Verify max superspines
                if nodeid >= self.max_superspine:
                    raise Exception(f"Superspine {node} exceeds maximum # superspines!")
            elif properties['role'] == 'dcgw':
                # Verify max dcgws
                if nodeid >= self.max_dcgw:
                    raise Exception(f"DCGW {node} exceeds maximum # DCGWs!")

                # Verify not using bgp-unnumbered as this is not supported due to SROS problem
                if self._topo.graph["bgp_unnumbered"]:
                    raise Exception("Using BGP-unnumbered is not supported in combination with DCGW integration.")

            # Validate podid
            if 'podid' in properties:
                if properties['podid'] >= self.max_pod:
                    raise Exception("Maximum number of pods exceeded!")

            # Allocate asn
            #
            # allocation scheme: (if not overridden)
            # | dcgws  | superspines | ---------- pod 1 ------------ | ---------- pod 2 ------------ | ...
            # |        |             | spines | borderleafs | leafs  | spines | borderleafs | leafs  | ...
            # | X asns | 1 asn       | 1 asn  | X asns      | X asns | 1 asn  | X asns      | X asns | ...
            #
            # where applicable, all spaces are reserved till max allowed /role /pod

            offset = nodeid if properties['role'] in ['dcgw', 'leaf', 'borderleaf'] else 0
            podoffset = 0
            roleoffset = 0

            if properties['role'] in ['spine', 'leaf', 'borderleaf']:
                podoffset = properties['podid'] * (1 + self.max_borderleaf_in_pod + self.max_leaf_in_pod)

            # reserve for dcgw
            roleoffset += self.max_dcgw if properties['role'] in ['spine', 'leaf', 'borderleaf', 'superspine'] else 0
            # reserve for superspine
            roleoffset += 1 if properties['role'] in ['spine', 'leaf', 'borderleaf'] else 0
            # reserve for spine in pod
            roleoffset += 1 if properties['role'] in ['leaf', 'borderleaf'] else 0
            # reserve for borderleaf in pod
            roleoffset += self.max_borderleaf_in_pod if properties['role'] in ['leaf'] else 0

            asn_offset = offset + podoffset + roleoffset

            # Allocate ASN
            if 'asn' not in properties:
                if node in self._overrides and 'asn' in self._overrides[node]:
                    allocated_asn = self._overrides[node]['asn']
                else:
                    # Grow asnpool with new items from generator if needed
                    while asn_offset >= len(asnpool):
                        curr = len(asnpool)
                        asnpool.extend(itertools.islice(asnpool_gen, 16))  # Extend with 16 more items (16 = arbitrary)
                        if len(asnpool) <= curr:
                            raise IndexError("asnpool exhausted!")

                    allocated_asn = asnpool[asn_offset]

                if allocated_asn in allocated_asns:
                    r, p = allocated_asns[allocated_asn]
                    if properties['role'] in ['leaf', 'borderleaf']:
                        # (border-)leafs and dcgws need their own ASN
                        raise Exception(f"ASN {allocated_asn} for {node} already in use!")
                    if allocated_asns[allocated_asn] != (properties['role'], properties['podid'] if 'podid' in properties else None,):
                        # for other roles, only allow reuse within same role, podid
                        raise Exception(f"ASN {allocated_asn} for {node} already in use!")
                self._topo.nodes[node]['asn'] = allocated_asn
                allocated_asns[allocated_asn] = (properties['role'], properties['podid'] if 'podid' in properties else None,)

            # Allocate loopback
            #
            # allocation scheme: (if not overridden)
            # | dcgws | superspines | ---------- pod 1 ----------- | ---------- pod 2 ----------- | ...
            # |       |             | spines | borderleafs | leafs | spines | borderleafs | leafs | ...
            #
            # all spaces are reserved till max allowed /role /pod

            offset = nodeid
            podoffset = 0
            roleoffset = 0

            if properties['role'] in ['spine', 'leaf', 'borderleaf']:
                podoffset = properties['podid'] * (self.max_spine_in_pod + self.max_borderleaf_in_pod + self.max_leaf_in_pod)

            # reserve for dcgw
            roleoffset += self.max_dcgw if properties['role'] in ['spine', 'leaf', 'borderleaf', 'superspine'] else 0
            # reserve for superspine
            roleoffset += self.max_superspine if properties['role'] in ['spine', 'leaf', 'borderleaf'] else 0
            # reserve for spine in pod
            roleoffset += self.max_spine_in_pod if properties['role'] in ['leaf', 'borderleaf'] else 0
            # reserve for borderleaf in pod
            roleoffset += self.max_borderleaf_in_pod if properties['role'] in ['leaf'] else 0

            loopback_offset = offset + podoffset + roleoffset

            # Allocate loopback
            if 'loopback' not in properties:
                if node in self._overrides and 'loopback' in self._overrides[node]:
                    allocated_loopback = str(netaddr.IPAddress(self._overrides[node]['loopback']))
                    overwrite_loopbacks.append(allocated_loopback)
                else:
                    allocated_loopback = str(loopback_pool[loopback_offset])

                if allocated_loopback in allocated_loopbacks:
                    raise Exception(f"Loopback address {allocated_loopback} already in use!")
                allocated_loopbacks.append(allocated_loopback)
                self._topo.nodes[node]['loopback'] = allocated_loopback

        # Summarize loopbacks that were specified with overrides
        if len(overwrite_loopbacks) > 0:
            to_summarize = list(overwrite_loopbacks)
            for loopback in self._topo.graph['loopback']:
                for address in overwrite_loopbacks:
                    if netaddr.IPAddress(address) in netaddr.IPNetwork(loopback):
                        to_summarize.remove(address)
            if len(to_summarize) > 0:
                for mask in range(32, 0, -1):
                    loopback = netaddr.IPNetwork(netaddr.IPNetwork(to_summarize[0] + "/" + str(mask)).network)
                    loopback.prefixlen = mask
                    if all([netaddr.IPAddress(address) in loopback for address in to_summarize]):
                        break
                else:
                    raise Exception(f"Unable to find mask that aggregates {to_summarize}!")
                self._topo.graph['loopback'].append(str(loopback))

        # Iterate over the network-graph edges for ISL-address assignment
        if not self._topo.graph['bgp_unnumbered']:
            roleorder = ["spine", "dcgw", "superspine", "borderleaf", "leaf"]  # used to allocate address within /31 p2p subnet to nodes.
            if isinstance(self._fabric_data['p2p'], list):
                p2ppool_gen = itertools.chain(*[netaddr.IPNetwork(x).subnet(31) for x in self._fabric_data['p2p']])
            else:
                p2ppool_gen = netaddr.IPNetwork(self._fabric_data['p2p']).subnet(31)
            # p2ppool_gen is a generator, could be huge!
            # convert genrator into list to allocate p2p from, initially the reserved space for DCGW (minimum 16), grows later
            p2ppool = list(itertools.islice(p2ppool_gen, max(16, 4 * self.max_dcgw)))

            # The allocation happens based on the usable ports in the spine layer since (almost) every p2p-link involves the spine layer.

            # allocation scheme:
            # | reserved range for | ------------- pod 1 ------------ | ------------- pod 2 ------------ | ...
            # | DCGW connected to  | spine1 | ... | max_spine_per_pod | spine1 | ... | max_spine_per_pod |
            # | superspine or      |                                  |                                  |
            # | borderleaf         |                                  |                                  |
            # | (not involving the |                                  |                                  |
            # | spine-layer)       |                                  |                                  |
            # |                    |                                  |                                  |
            # | max_isl_per_dcgw * |      max_spine_per_pod *         |      max_spine_per_pod *         |
            # |   max_dcgw         |           max_isl_per_spine      |           max_isl_per_spine      |

            for endpoint1, endpoint2, key, properties in self._topo.edges(data=True, keys=True):
                ep1_properties = self._topo.nodes[endpoint1]
                ep2_properties = self._topo.nodes[endpoint2]

                if ep1_properties['role'] == 'spine':
                    spineendpoint = endpoint1
                elif ep2_properties['role'] == 'spine':
                    spineendpoint = endpoint2
                else:
                    if self._topo.graph["single-tier"]:
                        # Single tier
                        # Allocate based on alphabetical sort of interface-names on leaf with lowest id
                        primary = endpoint1 if ep1_properties["id"] < ep2_properties["id"] else endpoint2
                        secondary = endpoint1 if primary == endpoint2 else endpoint2
                        primaryportorder = sorted([port for _, _, _, port in self._topo.edges([primary], data=primary, keys=True)])
                        offset = primaryportorder.index(properties[primary])
                        self._topo.edges[endpoint1, endpoint2, key]["p2p"] = str(p2ppool[offset])
                        self._topo.edges[endpoint1, endpoint2, key]["p2p_address"] = {
                            primary: str(p2ppool[offset][0]),
                            secondary: str(p2ppool[offset][1]),
                        }
                    else:
                        if ep1_properties['role'] == 'dcgw':
                            dcgwendpoint = endpoint1
                        elif ep2_properties['role'] == 'dcgw':
                            dcgwendpoint = endpoint2
                        else:
                            raise Exception(f"No idea how to allocate P2P between {endpoint1} and {endpoint2}")

                        dcgwportorder = sorted([port for _, _, _, port in self._topo.edges([dcgwendpoint], data=dcgwendpoint, keys=True)])
                        if len(dcgwportorder) > 4:
                            raise Exception("No more than 4 uplinks per DCGW allowed!")

                        nodeid = self._topo.nodes[dcgwendpoint]['id'] - 1  # make 0 based!
                        nodeoffset = dcgwportorder.index(properties[dcgwendpoint])
                        offset = (4 * nodeid) + nodeoffset

                        self._topo.edges[endpoint1, endpoint2, key]["p2p"] = str(p2ppool[offset])
                        self._topo.edges[endpoint1, endpoint2, key]["p2p_address"] = {
                            endpoint1: str(p2ppool[offset][0 if endpoint1 == dcgwendpoint else 1]),
                            endpoint2: str(p2ppool[offset][0 if endpoint2 == dcgwendpoint else 1]),
                            primary: str(p2ppool[offset][0]),
                            secondary: str(p2ppool[offset][1]),
                        }

                    continue

                nodeid = self._topo.nodes[spineendpoint]['id'] - 1  # make 0 based!
                podid = self._topo.nodes[spineendpoint]['podid']

                reserved_offset = self.max_isl_per_dcgw * self.max_dcgw
                podoffset = podid * self.max_spine_in_pod * self.max_isl_per_spine
                nodeoffset = nodeid * self.max_isl_per_spine

                try:
                    portoffset = self._spine_islports[spineendpoint].index(properties[spineendpoint])
                except ValueError:
                    raise Exception(f"Used an invalid port {properties[spineendpoint]} as ISL on spine {spineendpoint}")

                offset = reserved_offset + podoffset + nodeoffset + portoffset

                # Grow p2ppool with new items from generator if needed
                while offset >= len(p2ppool):
                    curr = len(p2ppool)
                    p2ppool.extend(itertools.islice(p2ppool_gen, 16))  # Extend with 16 more items (16 = arbitrary)
                    if len(p2ppool) <= curr:
                        raise IndexError("p2ppool exhausted!")

                self._topo.edges[endpoint1, endpoint2, key]["p2p"] = str(p2ppool[offset])

                ep1index = (roleorder.index(ep1_properties["role"]), ep1_properties["id"])
                ep2index = (roleorder.index(ep2_properties["role"]), ep2_properties["id"])
                self._topo.edges[endpoint1, endpoint2, key]["p2p_address"] = {
                    endpoint1: str(p2ppool[offset][0 if ep1index < ep2index else 1]),
                    endpoint2: str(p2ppool[offset][0 if ep2index < ep1index else 1]),
                }

        # Fourth pass through the network-graph nodes for BGP peering calculation
        nodeproperties = self._topo.nodes(data=True)
        for node, properties in self._topo.nodes(True):
            nodeid = properties['id'] - 1  # make 0 based!
            self._topo.nodes[node]["bgp"] = dict()
            self._topo.nodes[node]["bgp"]["groups"] = dict()

            # Underlay peer via ISLs
            underlay_peergroups = dict()
            for n1, n2, key, edgeproperties in self._topo.edges([node], data=True, keys=True):
                peer = n2 if node == n1 else n2
                peergroup = nodeproperties[peer]["role"]
                if peergroup not in underlay_peergroups:
                    underlay_peergroups[peergroup] = list()
                if not self._topo.graph['bgp_unnumbered']:
                    underlay_peergroups[peergroup].append((edgeproperties["p2p_address"][peer], nodeproperties[peer]["asn"],))
                else:
                    underlay_peergroups[peergroup].append((edgeproperties[node], nodeproperties[peer]["asn"],))

            for peergroup, peers in underlay_peergroups.items():
                if peergroup not in self._topo.nodes[node]["bgp"]["groups"]:
                    self._topo.nodes[node]["bgp"]["groups"][f"{peergroup}s"] = dict()
                    self._topo.nodes[node]["bgp"]["groups"][f"{peergroup}s"]["dynamic"] = dict()
                    self._topo.nodes[node]["bgp"]["groups"][f"{peergroup}s"]["neighbors"] = dict()
                    self._topo.nodes[node]["bgp"]["groups"][f"{peergroup}s"]["type"] = "underlay"
                    self._topo.nodes[node]["bgp"]["groups"][f"{peergroup}s"]["description"] = f"Peer-group for {peergroup} neighbors"
                if not self._topo.graph['bgp_unnumbered']:
                    peer_asns = list({asn for _, asn in peers})
                    for neighbor, asn in peers:
                        self._topo.nodes[node]["bgp"]["groups"][f"{peergroup}s"]["neighbors"][neighbor] = dict()
                        if len(peer_asns) > 1:
                            self._topo.nodes[node]["bgp"]["groups"][f"{peergroup}s"]["neighbors"][neighbor]["peer_as"] = asn
                    if len(peer_asns) == 1:
                        self._topo.nodes[node]["bgp"]["groups"][f"{peergroup}s"]["peer_as"] = peer_asns[0]
                else:
                    for interface, asn in peers:
                        self._topo.nodes[node]["bgp"]["groups"][f"{peergroup}s"]["dynamic"][interface] = dict()
                        self._topo.nodes[node]["bgp"]["groups"][f"{peergroup}s"]["dynamic"][interface]["allow-as"] = [asn]

            # Overlay
            self._topo.nodes[node]["bgp"]["groups"]["overlay"] = dict()
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["dynamic"] = dict()
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["neighbors"] = dict()
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["type"] = "overlay"
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["local_as"] = self._topo.graph["overlay_asn"]
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["peer_as"] = self._topo.graph["overlay_asn"]
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["local_address"] = properties["loopback"]
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["cluster_id"] = properties["loopback"]

            if self._fabric_data["rr"]["location"] == 'spine':
                neighborlist = list()
                # Spines peer with all (border-)leafs in pod
                if properties['role'] == 'spine':
                    neighborlist = self._topo.graph["pods"][properties["podid"]]["leaf"] + self._topo.graph["pods"][properties["podid"]]["borderleaf"]
                    # If there is more then 1 pod, also full interconnect all spines
                    if len(self._topo.graph["pods"]) > 1:
                        for podid in self._topo.graph["pods"]:
                            neighborlist.extend(self._topo.graph["pods"][podid]["spine"])
                    # Also peer with DCGWs
                    neighborlist.extend(self.dcgws)

                # (Border-)leafs peer with all spines in pod (unless in single tier, they peer with the other leaf)
                elif properties['role'] in ['leaf', 'borderleaf']:
                    if self._topo.graph["single-tier"]:
                        neighborlist = list(set(self._topo.graph["pods"][properties["podid"]]["leaf"]).difference({node}))
                    else:
                        neighborlist = self._topo.graph["pods"][properties["podid"]]["spine"]

                # DCGW peer with all spines
                elif properties['role'] == 'dcgw':
                    neighborlist = [x for podid in self._topo.graph["pods"] for x in self._topo.graph["pods"][podid]["spine"]]

                neighbor_addresses = [nodeproperties[n]["loopback"] for n in neighborlist]

            elif self._fabric_data["rr"]["location"] == 'external' and "neighbor_list" in self._fabric_data["rr"]:
                if properties['role'] in ['leaf', 'borderleaf', 'dcgw']:
                    neighbor_addresses = self._fabric_data["rr"]["neighbor_list"]

            elif self._fabric_data["rr"]["location"] == 'borderleaf':
                neighborlist = list()
                # Borderleafs peer with all leafs in pod
                if properties['role'] == 'borderleaf':
                    neighborlist = self._topo.graph["pods"][properties["podid"]]["leaf"]
                    # If there is more then 1 pod, also full interconnect all borderleafs
                    if len(self._topo.graph["pods"]) > 1:
                        for podid in self._topo.graph["pods"]:
                            neighborlist.extend(self._topo.graph["pods"][podid]["borderleaf"])
                    # Also peer with DCGWs
                    neighborlist.extend(self.dcgws)

                # Leafs peer with all borderleafs in pod
                elif properties['role'] == 'leaf':
                    neighborlist = self._topo.graph["pods"][properties["podid"]]["borderleaf"]

                # DCGW peer with all borderleafs
                elif properties['role'] == 'dcgw':
                    neighborlist = [x for podid in self._topo.graph["pods"] for x in self._topo.graph["pods"][podid]["borderleaf"]]

                neighbor_addresses = [nodeproperties[n]["loopback"] for n in neighborlist]
            else:
                raise Exception('Unable to determine overlay route reflection!')

            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["neighbors"] = dict(zip(neighbor_addresses, itertools.repeat(dict(), len(neighbor_addresses))))


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}

        result = super().run(tmp, task_vars)
        del tmp  # tmp no longer has any effect

        if not HAS_NX:
            result["failed"] = True
            result["msg"] = missing_required_lib("networkx")
            result["exception"] = NX_IMP_ERR
            return result

        if not HAS_NETADDR:
            result["failed"] = True
            result["msg"] = missing_required_lib("netaddr")
            result["exception"] = NETADDR_IMP_ERR
            return result

        groups = task_vars.get("groups", {})
        fabric_intent = self._task.args.get("fabric_intent", None)
        fabric_nodes = {group: nodelist for group, nodelist in groups.items() if group in ['spine', 'leaf', 'superspine', 'dcgw', 'borderleaf']}

        ipfabric = IpFabricParser(
            fabric_nodes=fabric_nodes,
            fabric_intent=fabric_intent,
            )
        result.update(ipfabric.processed_fabric)

        return result
