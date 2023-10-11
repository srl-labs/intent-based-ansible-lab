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
def expand_range(inp, hint=None):
    ret = list()
    if hint is None:
        hint = list()
    r_re = re.compile(r"\[(?P<start>\d+)(-|\.\.)(?P<stop>\d+)\]")
    r_match = r_re.search(inp)
    if r_match is None:
        ret.append(inp)
    else:
        r_start = int(r_match["start"])
        r_end = int(r_match["stop"]) + 1
        if r_end <= r_start:
            raise Exception("Invalid range in entry in edge_interfaces")
        for i in range(r_start, r_end):
            if len(hint) > 0:
                # When hints are given (known hostnames), try anywhere between 0-3 leading zeros to see if there ia a match
                # e.g. leaf[1-2] matches (leaf1, leaf2) but also (leaf001, leaf002)
                for j in range(1, 4):
                    fmtstr = "{:0%sd}" % j
                    outp = r_re.sub(fmtstr.format(i), inp)
                    if outp in hint:
                        ret.append(outp)
                        break
                else:
                    ret.append(r_re.sub(str(i), inp))
            else:
                ret.append(r_re.sub(str(i), inp))
    return ret


class IpFabricParser:
    def __init__(self, fabric_nodes, fabric_data, advanced_opts=None):
        if not isinstance(fabric_nodes, dict):
            raise AttributeError("Wrong type for fabric_nodes")
        for key in fabric_nodes.keys():
            if key not in ['spine', 'leaf', 'superspine', 'dcgw', 'borderleaf']:
                raise AttributeError("Wrong key in fabric_nodes")
        if not isinstance(fabric_data, dict):
            raise AttributeError("Wrong type for fabric_data")
        if advanced_opts is None:
            advanced_opts = {}

        default_options = {
            "max_pod": 1,
            "max_dcgw": 2,
            "max_superspine": 0,
            "max_spine_in_pod": 2,
            "max_borderleaf_in_pod": 2,
            "max_leaf_in_pod": 12,
            "dynamic_max_leaf_in_pod": False,
            "hardware": {
                "IXR_D3": {
                    "isl_ports": list([f"ethernet-1/{x+3}" for x in range(32)]),
                    "max_leaf": 12
                },
                "IXR_D3L": {
                    "isl_ports": list([f"ethernet-1/{x+1}" for x in range(32)]),
                    "max_leaf": 12
                },
                "IXR_H2": {
                    "isl_ports": list([f"ethernet-1/{x+1}" for x in itertools.chain(range(24), range(56, 88), range(120, 128))]),
                    "max_leaf": 12
                },
            },
        }

        self._fabric_nodes = fabric_nodes
        self._fabric_data = fabric_data
        self._advanced_opts = dict(default_options)
        self._advanced_opts.update(advanced_opts)
        self._hardware = dict()
        self._edge_interfaces = dict()
        self._parse_topo()

    @property
    def options(self):
        return deepcopy(self._advanced_opts)

    @property
    def max_pod(self):
        return self._advanced_opts['max_pod']

    @property
    def max_dcgw(self):
        return self._advanced_opts['max_dcgw']

    @property
    def max_superspine(self):
        return self._advanced_opts['max_superspine']

    @property
    def max_spine_in_pod(self):
        return self._advanced_opts['max_spine_in_pod']

    @property
    def max_borderleaf_in_pod(self):
        return self._advanced_opts['max_borderleaf_in_pod']

    @property
    def fabric_data(self):
        return deepcopy(self._fabric_data)

    @property
    def fabric_nodes(self):
        return deepcopy(self._fabric_nodes)

    @property
    def ipfabric_nodes(self):
        return deepcopy(self._ipfabric_nodes)

    @property
    def edge_interfaces(self):
        return deepcopy(self._edge_interfaces)

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
            ret[node]["edge_interfaces"] = deepcopy(self._edge_interfaces[node]) if node in self._edge_interfaces else dict()
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

    def max_leaf_in_pod(self, pod=0):
        if "single-tier" in self._topo.graph and self._topo.graph["single-tier"]:
            return min(self._advanced_opts['max_leaf_in_pod'], 2)
        if not self._advanced_opts['dynamic_max_leaf_in_pod']:
            return self._advanced_opts['max_leaf_in_pod']
        else:
            if pod >= min(len(self._topo.graph["pods"]), self.max_pod):
                return 0
            max_leaf_in_pod = self._advanced_opts['hardware'][self._topo.graph["pods"][pod]["spine_hardware"]]['max_leaf']
            return min(self._advanced_opts['max_leaf_in_pod'], max_leaf_in_pod)

    def _parse_topo(self):
        shortport_re = re.compile(r"^e?([\d]+)[-/]([\d]+)$")

        self._topo = nx.MultiGraph()
        self._topo.graph["overlay_asn"] = int(self._fabric_data["overlay_asn"])
        self._topo.graph["pods"] = dict()

        # Populate network-graph with nodes fabric_nodes (from ansible inventory)
        for nodetype, nodelist in self._fabric_nodes.items():
            self._topo.add_nodes_from([(node, {"role": nodetype},) for node in nodelist])
        self._topo.graph["single-tier"] = len(self.leafs) == 2 and len(self.nodes) == 2

        # Parse HW info
        for entry in self._fabric_data['hardware']:
            for node in expand_range(entry, self.nodes):
                if node in self.nodes:
                    self._hardware[node] = self._fabric_data['hardware'][entry]

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
            if 'overrides' in self._fabric_data and node in self._fabric_data['overrides'] and 'id' in self._fabric_data['overrides'][node]:
                nodeid = self._fabric_data['overrides'][node]['id']
            else:
                nodeid = int(re.search(r"\d+$", node)[0])
            self._topo.nodes[node]["id"] = nodeid

            # Add hardware property
            if node in self._hardware:
                self._topo.nodes[node]["hardware"] = self._hardware[node]
            else:
                if properties['role'] == 'spine':
                    raise Exception(f"Not able to determine hardware for spine {node}")

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
                    self._topo.graph["pods"][podid]["spine_hardware"] = self._topo.nodes[spines_in_pod[0]]["hardware"]
                    self._topo.graph["pods"][podid]["spine"] = spines_in_pod
                    self._topo.graph["pods"][podid]["leaf"] = list()
                else:
                    self._topo.graph["pods"][podid]["spine_hardware"] = None
                    self._topo.graph["pods"][podid]["spine"] = list()
                    self._topo.graph["pods"][podid]["leaf"] = list()
                self._topo.graph["pods"][podid]["borderleaf"] = list()

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
                    if self._topo.nodes[spine]["hardware"] != self._topo.graph["pods"][podid]["spine_hardware"]:
                        raise Exception(f"Not all spines in pod {podid} have same HW type!")

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
            elif properties['role'] == 'leaf':
                # Verify max leafs in pod
                if nodeid >= self.max_leaf_in_pod(properties['podid']):
                    raise Exception(f"Leaf {node} exceeds maximum # leafs in pod!")
            elif properties['role'] == 'borderleaf':
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
            # for leafs, the max allowed /pod can be either static, or dynamic based on HW type used in spine layer

            offset = nodeid if properties['role'] in ['dcgw', 'leaf', 'borderleaf'] else 0
            podoffset = 0
            roleoffset = 0

            if properties['role'] in ['spine', 'leaf', 'borderleaf']:
                podoffset = sum([1 + self.max_borderleaf_in_pod + self.max_leaf_in_pod(i) for i in range(properties['podid'])])

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
                if 'overrides' in self._fabric_data and node in self._fabric_data['overrides'] and 'asn' in self._fabric_data['overrides'][node]:
                    allocated_asn = self._fabric_data['overrides'][node]['asn']
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
            # for leafs, the max allowed /pod can be either static, or dynamic based on HW type used in spine layer

            offset = nodeid
            podoffset = 0
            roleoffset = 0

            if properties['role'] in ['spine', 'leaf', 'borderleaf']:
                podoffset = sum([self.max_spine_in_pod + self.max_borderleaf_in_pod + self.max_leaf_in_pod(i) for i in range(properties['podid'])])

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
                if 'overrides' in self._fabric_data and node in self._fabric_data['overrides'] and 'loopback' in self._fabric_data['overrides'][node]:
                    allocated_loopback = str(netaddr.IPAddress(self._fabric_data['overrides'][node]['loopback']))
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
        self._topo.graph['bgp_unnumbered'] = 'p2p' not in self._fabric_data or len(self._fabric_data['p2p']) == 0
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
            # | superspine or      |          \                       |          \                       |
            # | borderleaf         | max isl-   \                     | max isl-   \                     |
            # | (not involving the | capable port \                   | capable port \                   |
            # | spine-layer)       | for hardware   \                 | for hardware   \                 |

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

                reserved_offset = 4 * self.max_dcgw  # max 4 links per dcgw (e.g. 4x 100G)
                podoffset = sum([self.max_spine_in_pod * len(self._advanced_opts['hardware'][self._topo.graph["pods"][x]["spine_hardware"]]['isl_ports'])
                                 for x in range(podid)])
                nodeoffset = nodeid * len(self._advanced_opts['hardware'][self._topo.graph["pods"][podid]["spine_hardware"]]['isl_ports'])
                try:
                    spinehw = self._topo.graph["pods"][podid]["spine_hardware"]
                    portoffset = self._advanced_opts['hardware'][spinehw]['isl_ports'].index(properties[spineendpoint])
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
            for n1, n2, key, edgeproperties in self._topo.edges([node], data=True, keys=True):
                peer = n2 if node == n1 else n2
                peergroup = nodeproperties[peer]["role"] + "s"
                if peergroup not in self._topo.nodes[node]["bgp"]["groups"]:
                    self._topo.nodes[node]["bgp"]["groups"][peergroup] = dict()
                    self._topo.nodes[node]["bgp"]["groups"][peergroup]["dynamic"] = dict()
                    self._topo.nodes[node]["bgp"]["groups"][peergroup]["neighbors"] = dict()
                    self._topo.nodes[node]["bgp"]["groups"][peergroup]["type"] = "underlay"
                    self._topo.nodes[node]["bgp"]["groups"][peergroup]["description"] = f"Peer-group for {nodeproperties[peer]['role']} neighbors"
                if not self._topo.graph['bgp_unnumbered']:
                    neighbor = edgeproperties["p2p_address"][peer]
                    self._topo.nodes[node]["bgp"]["groups"][peergroup]["neighbors"][neighbor] = dict()
                    if nodeproperties[peer]["role"] in ['superspine', 'spine']:
                        self._topo.nodes[node]["bgp"]["groups"][peergroup]["peer_as"] = nodeproperties[peer]["asn"]
                    else:
                        self._topo.nodes[node]["bgp"]["groups"][peergroup]["neighbors"][neighbor]["peer_as"] = nodeproperties[peer]["asn"]
                else:
                    interface = edgeproperties[node]
                    self._topo.nodes[node]["bgp"]["groups"][peergroup]["dynamic"][interface] = dict()
                    self._topo.nodes[node]["bgp"]["groups"][peergroup]["dynamic"][interface]["allow-as"] = [nodeproperties[peer]["asn"]]

            # Overlay
            self._topo.nodes[node]["bgp"]["groups"]["overlay"] = dict()
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["dynamic"] = dict()
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["neighbors"] = dict()
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["type"] = "overlay"
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["local_as"] = self._topo.graph["overlay_asn"]
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["peer_as"] = self._topo.graph["overlay_asn"]
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["local_address"] = properties["loopback"]
            self._topo.nodes[node]["bgp"]["groups"]["overlay"]["cluster_id"] = properties["loopback"]

            if "rr" not in self._fabric_data or "location" not in self._fabric_data["rr"] or self._fabric_data["rr"]["location"] == 'spine':
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

            elif "rr" in self._fabric_data and "location" in self._fabric_data["rr"] and \
                    self._fabric_data["rr"]["location"] == 'external' and "neighbor_list" in self._fabric_data["rr"]:
                if properties['role'] in ['leaf', 'borderleaf', 'dcgw']:
                    neighbor_addresses = self._fabric_data["rr"]["neighbor_list"]

            elif "rr" in self._fabric_data and "location" in self._fabric_data["rr"] and self._fabric_data["rr"]["location"] == 'borderleaf':
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

        # Parse edge_interfaces
        edgenodes = self.leafs + self.borderleafs
        if 'edge_interfaces' in self._fabric_data and isinstance(self._fabric_data['edge_interfaces'], list):
            for entry in self._fabric_data['edge_interfaces']:
                if not isinstance(entry, dict):
                    raise AttributeError("Wrong datatype for entry in edge_interfaces")
                if not set.issubset({'nodes', 'interfaces'}, entry.keys()):
                    raise AttributeError("Wrong data for entry in edge_interfaces")
                for node in expand_range(entry["nodes"], hint=edgenodes):
                    if node not in self._edge_interfaces:
                        self._edge_interfaces[node] = dict()
                    for iface in expand_range(entry["interfaces"]):
                        interface = shortport_re.sub(r"ethernet-\g<1>/\g<2>", iface)
                        # TODO: breakout
                        self._edge_interfaces[node][interface] = {k: v for k, v in entry.items() if k not in {"nodes", "interfaces"}}


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
        fabric_intent = self._task.args.get("fabric_intent", {})
        fabric_data = fabric_intent.get("fabric", None)
        advanced_opts = fabric_intent.get("advanced_opts", {})

        if fabric_data is None:
            result["failed"] = True
            result["msg"] = "No fabric_data found."
            return result

        fabric_nodes = {group: nodelist for group, nodelist in groups.items() if group in ['spine', 'leaf', 'superspine', 'dcgw', 'borderleaf']}

        ipfabric = IpFabricParser(
            fabric_nodes=fabric_nodes,
            fabric_data=fabric_data,
            advanced_opts=advanced_opts)
        result.update(ipfabric.processed_fabric)

        return result
