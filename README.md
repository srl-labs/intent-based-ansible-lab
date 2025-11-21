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

## Choose how to run

- **Codespaces:** click the button above and wait for the devcontainer to finish. Everything below is run from the repo root inside Codespaces.
- **Local machine:** follow the prerequisites and setup below, then run the same workflow.

## Local prerequisites

1) Containerlab installed. See the [official docs](https://containerlab.srlinux.dev/install/).
2) Git, Docker, and uv.

> [!TIP]
> **Why uv?**
> [uv](https://docs.astral.sh/uv) is a single, ultra-fast tool that can replace `pip`, `pipx`, `virtualenv`, `pip-tools`, `poetry`, and more. It automatically manages Python versions, handles ephemeral or persistent virtual environments (`uv venv`), lockfiles, and often runs **10–100× faster** than pip installs.

## Local setup

```bash

# Install uv (Linux/macOS)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install the Nokia SR Linux Ansible collection
uv run ansible-galaxy collection install nokia.srlinux

# Install the fcli tool
uv tool install git+https://github.com/srl-labs/nornir-srl
```

## Quick Start Guide

1. Deploy the lab topology:
```
clab deploy -t topo.clab.yml
``` 
2. Run the Ansible playbook:
```
INTENT_DIR=$(pwd)/intent_examples/infra/underlay_with_fabric_intent
uv run ansible-playbook -i inv/ -e intent_dir=$INTENT_DIR --diff playbooks/cf_fabric.yml
``` 

3. Verify with fcli
```
fcli ni
``` 

4. Run other Ansible playbook described here:
``` 
https://learn.srlinux.dev/tutorials/programmability/ansible/intent-based-management/config/
```