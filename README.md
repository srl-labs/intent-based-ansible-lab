# Intent-based fabric management with Ansible

A practical example of using Ansible to manage the configuration of an SR Linux fabric with the **intent-based approach** leveraging the official Ansible collection for SR Linux - read the [tutorial on learn.srlinux.dev](http://learn.srlinux.dev/tutorials/programmability/ansible/intent-based-management) for a complete walkthrough of this project.



---
<div align=center>
<a href="https://codespaces.new/srl-labs/intent-based-ansible-lab?quickstart=1">
<img src="https://gitlab.com/rdodin/pics/-/wikis/uploads/d78a6f9f6869b3ac3c286928dd52fa08/run_in_codespaces-v1.svg?sanitize=true" style="width:50%"/></a>

**[Run](https://codespaces.new/srl-labs/intent-based-ansible-lab?quickstart=1) this lab in GitHub Codespaces for free**.  
[Learn more](https://containerlab.dev/manual/codespaces/) about Containerlab for Codespaces.

</div>

---

## Quick Start Guide to run in codespaces

1. Deploy the lab topology:
```
sudo clab deploy -t topo.yml
``` 
2. Run the Ansible playbook:
```
ansible-playbook -i inv/ -e intent_dir=/workspaces/codespacetest/intent-based-ansible-lab/intent_examples/infra/underlay_with_fabric_intent --diff playbooks/cf_fabric.yml
``` 