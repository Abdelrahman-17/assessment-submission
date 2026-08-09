# Task 4: Ansible Basics Lab — Inventory and Simple Playbook

## Objective

This bonus task demonstrates the basic Ansible workflow requested in the technical assessment:

- Inventory definition for two hosts
- Connectivity testing with `ansible -m ping`
- Fact gathering
- Display of hostname, OS family, IP address and uptime
- Package installation (`curl`)
- Directory creation under `/tmp`
- File deployment
- SSH/SSHD service discovery and status reporting
- Idempotent playbook execution

## Files

```text
task-4-ansible-bonus/
├── inventory.ini
├── basic_setup.yml
└── README.md
```

## Environment note

The submitted inventory uses Ansible's `local` connection for `vm1` and `vm2` because the assessment lab used one available Linux control host rather than two separately addressable VMs. This demonstrates the required Ansible workflow and idempotency without requiring Docker.

For a real two-VM lab, replace the two inventory entries with the actual VM IP addresses and SSH settings, for example:

```ini
[webservers]
vm1 ansible_host=192.168.56.101 ansible_user=ubuntu
vm2 ansible_host=192.168.56.102 ansible_user=ubuntu
```

## Requirements

- Ansible installed on the control machine
- Python 3 on managed hosts
- `sudo`/privilege escalation when required
- For remote VMs: SSH access and valid credentials/key

## Run

From this directory:

```bash
ansible all -i inventory.ini -m ping
```

Then run the playbook:

```bash
ansible-playbook -i inventory.ini basic_setup.yml -K
```

Run it a second time:

```bash
ansible-playbook -i inventory.ini basic_setup.yml
```

The second run should normally report fewer changes because the directory, file and package are already in the desired state.

## What the playbook does

1. Gathers Ansible facts.
2. Prints hostname, OS family, IP address and calculated uptime.
3. Creates `/tmp/ansible_lab`.
4. Deploys `/tmp/ansible_lab/motd.txt`.
5. Installs `curl` using Ansible's cross-platform `package` module.
6. Uses `service_facts` to discover either `ssh.service` or `sshd.service` and reports its state without unnecessarily changing the service.
7. Verifies that the deployed file exists.

## Expected evidence

Capture terminal output showing:

```text
ansible all -i inventory.ini -m ping
```

followed by the playbook execution and preferably a second playbook execution showing reduced/no changes.

## Notes

The inventory is intentionally simple. The task is a basic Ansible awareness exercise, not a production automation framework.
