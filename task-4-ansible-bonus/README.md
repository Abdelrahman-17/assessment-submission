# Task 4: Ansible Basics Lab — Inventory and Simple Playbook

## 🎯 Overview
A complete Ansible lab demonstrating core automation workflows, including custom inventory definition, facts gathering, directory provisioning, file deployment, package installation, and service status verification.

---

## ⚙️ How to Run & Test

1. **Navigate to the task folder:**
   ```bash
   cd task-4-ansible-bonus
Test SSH/Local Connectivity (Ping Test):

Bash
ansible all -i inventory.ini -m ping
Run the Playbook (Idempotency Check):
Run the playbook twice to demonstrate that the second execution results in changed=0 (Idempotency):

Bash
ansible-playbook -i inventory.ini basic_setup.yml
