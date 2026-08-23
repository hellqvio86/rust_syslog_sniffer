# K3s Node Scheduling Hardening

This Ansible setup applies a simple scheduling policy for self-managed k3s clusters:

- Cordon all control-plane nodes
- Taint control-plane nodes with:
  - `node-role.kubernetes.io/control-plane=:NoSchedule`
  - `node-role.kubernetes.io/master=:NoSchedule`
- Label worker nodes with:
  - `workload=apps`

This keeps normal workloads off control-plane nodes while still allowing DaemonSets that tolerate control-plane taints.

## Prerequisites

- `ansible-core` installed on the machine running this playbook
- `kubectl` installed and configured (`KUBECONFIG`) with cluster-admin access

## Run

```bash
cd ansible
ansible-playbook playbooks/k3s-node-scheduling.yml
```

## Verify

```bash
kubectl get nodes --show-labels
kubectl describe node <control-plane-node> | grep -i -E 'Unschedulable|Taints'
kubectl get pods -A -o wide
```
