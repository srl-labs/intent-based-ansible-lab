# Intent-based fabric management with Ansible

A practical example of using Ansible to manage the configuration of an SR Linux fabric with the **intent-based approach** leveraging the official Ansible collection for SR Linux - read the [tutorial on learn.srlinux.dev](http://learn.srlinux.dev/tutorials/programmability/ansible/intent-based-management) for a complete walkthrough of this project.


## Latest developments

Check the [repo issues](https://github.com/srl-labs/intent-based-ansible-lab/issues) for what is planned. Chime in if you have additional ideas (create a new issue) or comment on existing issues.

For a sneak preview of the latest developments, clone the `dev` instead of the `main` branch:

```bash
git clone -b dev https://github.com/srl-labs/intent-based-ansible-lab.git
cd intent-based-ansible-lab
python3 -mvenv .venv
source .venv/bin/activate
pip install -U pip && pip install -r requirements.txt
ansible-galaxy collection install nokia.srlinux
```

Main differences:

* restructured inventory: all host_vars are now included in the single ansible inventory file [ansible-inventory.yml](https://github.com/srl-labs/intent-based-ansible-lab/blob/dev/inv/ansible-inventory.yml). This is for ease-of-use to have all node-specfic vars in a single file
* intents are stored in a  dedicated directory `./intent/${ENV}` in the playbook dir[^1]. Previously, these were stored in the role-specific `vars` directory under the role directory. Below is an example for `ENV=test`. 

    ```bash
    intent
    └── test
        ├── group_infra.yml
        ├── host_infra.yml
        ├── l2vpn.yml
        ├── l3vpn_2001.yml
        └── l3vpn_2002.yml
    ``` 
    * all host-specific low-level intents are stored in the `host_infra.yml` file. The group-level low-level intents are in the `group_infra.yml`
    * Also high-level service-intents are stored here. They can be stored in separate files (e.g. 1 per service-instance) as is the case for 'l3vpn', or in a single file like in `l2vpn.yml`. Roles look for 'l2vpn' or 'l3vpn' in filenames to associate respective intents.

* Restructured roles and main playbook. To address `ansible-lint` rules, roles are no longer stored in hierarchical directories but directly under the `roles` directory.
* Behaviour change for l2vpn: if all associated mac-vrfs associated with l3vpn subnets are not in the l2vpn-intent or have `_state: deleted`, the l3vpn service will not be created or will be deleted if it existed before. When the mac-vrfs are created or have their deleted state removed, the ipvrf service with spring into existence.
* Added **schema validation** of user-provided intents (in intent directory). Schemas are provided for the `infra`, `l2vpn` and `l3vpn` roles inside the `./criteria` directory relative to the role.
* Support for **BGP unnumbered** in underlay. Matching intent in `intent/bgp_unnumbered`. (Re)Configure underlay from static-v4 bgp-routing (`ENV=test`) to dynamic-v4 using ipv6-LLA addresses (`ENV=bgp_unnumbered`) and vice-versa.
* Support for **EVPN multi-homing** via the `mh_access` L2 intent. There is a 1:N mapping between a MH_ACCESS instance and L2VPN services. See `./intent/test/mh_access.yml` for examples
* Support for **IPv4 ACLs**. Definition of ACLs via `roles/rpc_acl` with data-model defined in `roles/infra/criteria/acl_filters.json`. ACL definitions are thus entered via L1-intent in `group_infra.yml` and/or `host_infra.yml`. ACL association with subinterfaces via same L1 intent and validated by schema in `roles/infra/criteria/subinterface.json`. ACL association with L2 intents (l2vpn, l3vpn) validated via `roles/`*svc_type*`/criteria/`*svc_type*`.json`.
* Support for **fabric intent**. Build complete DC Fabric infrastructure (underlay routing, overlay routing, ISL-addressing, matching route-policies) from a high-level fabric-intent (Example in `./intent/fabric_test`)
* Limited support for SROS to support DCGW interconnection with the fabric. Use of `ansible.netcommon.netconf` to push/get configuration. See var `sros` in `group_infra` under `./intent/dcgw_test` 
* bug fixing

[^1]: Intents could have been placed in Ansible `host_vars` and `group_vars` but issues arise when variables are redefined as is the case in host- and group-level intents, due to the hierarchical nature of the variables/device model (e.g. `.network-instance.protocols.bgp` has host-level and group-level definitions but it's a single variable `network-instance`). It requires that variables are *merged* rather than *replaced* which is the default behavior with ansible's `host_vars` and `group_vars`. This behavior can be controlled via `hash_bahaviour=merge` in the `ansible.cfg` file. Ansible development discorages setting this playbook-wide parameter as existing modules and roles assume the default `replace` behavior and may deprecate this option in later releases. To achieve the desired behavior, the `combine` filter is proposed, which is exactly what we're doing in the roles of this playbook.
