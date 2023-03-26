## Goal

Show how configuration management across lifecyle of a fabric could be done via Ansible.

## Setup

### Prequisites

- Python environment with minimal ansible-core installation
```
mkdir 4l2s
python3 -mvenv .venv
source .venv/bin/activate
```
- containerlab: launch virtual lab with `sudo clab -c -t 4l2s.clab.yaml` 
- nokia.srl Ansible collection that includes the `jsonrpc-set` and `jsonrpc-get` modules. See [srl-ansible-collection](https://github.com/srl-labs/srl-ansible-collection) for details

### Usage

- manual mapping of Ansible inventory to clab topo. See `./inv` for inventory variables, host and group definitions.
- intents are split between `infra` and `services` intents in `./infra/*/vars` and `./services/*/vars`.
- `infra` intents are low-level intents close to device model for `interface`, `subinterface`, `routing-policy` and `network-instance` resource instances
- `services` intents are high-level intents for `l2vpn` and `l3vpn` service types

Main playbook `cf_fabric.yml` calls individual ansible roles for intialization, low-level intent generation (infra + services) and finally configuration push.
An example of invocation is:

```
ansible-playbook --diff cf_fabric.yml
PLAY [Configure fabric] ******************************************************************************************************************

TASK [infra/interface: Load Intent for /interfaces] ***********************************************************************************************

TASK [infra/policy: Load Intent: /routing-policy] *************************************************************************************************

TASK [infra/networkinstance: load Intent: /network-instance] **************************************************************************************

TASK [services/l3vpn: Generate config for /interface] *********************************************************************************************

TASK [services/l3vpn: Generate config for /network-instance] **************************************************************************************

TASK [common/configure: Generate config for /interface] *******************************************************************************************

TASK [common/configure: Generate config for /network-instance] ************************************************************************************

TASK [common/configure: Generate config for /routing-policy] **************************************************************************************

PLAY RECAP *****************************************************************************************************************
clab-4l2s-l1               : ok=38   changed=0    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0   
clab-4l2s-l2               : ok=32   changed=0    unreachable=0    failed=0    skipped=7    rescued=0    ignored=0   
clab-4l2s-l3               : ok=28   changed=0    unreachable=0    failed=0    skipped=11   rescued=0    ignored=0   
clab-4l2s-l4               : ok=38   changed=0    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0   
clab-4l2s-s1               : ok=28   changed=0    unreachable=0    failed=0    skipped=11   rescued=0    ignored=0   
clab-4l2s-s2               : ok=28   changed=0    unreachable=0    failed=0    skipped=11   rescued=0    ignored=0   


CUSTOM STATS: *************************************************************************************************************
        clab-4l2s-l1: { "network_instance": "6", "routing_policy": "2", "subinterface": "9", "sw_version": "v23.3.1"}
        clab-4l2s-l2: { "network_instance": "2", "routing_policy": "2", "subinterface": "5", "sw_version": "v23.3.1"}
        clab-4l2s-l3: { "network_instance": "1", "routing_policy": "2", "subinterface": "5", "sw_version": "v23.3.1"}
        clab-4l2s-l4: { "network_instance": "5", "routing_policy": "2", "subinterface": "8", "sw_version": "v23.3.1"}
        clab-4l2s-s1: { "network_instance": "1", "routing_policy": "2", "subinterface": "5", "sw_version": "v23.3.1"}
        clab-4l2s-s2: { "network_instance": "1", "routing_policy": "2", "subinterface": "5", "sw_version": "v23.3.1"}
```

