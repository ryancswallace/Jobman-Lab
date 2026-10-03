SHELL := /bin/bash
.DEFAULT_GOAL := help

LAB_GROUP ?= full
VAGRANT_ENV := JOBMAN_LAB_GROUP=$(LAB_GROUP) VAGRANT_DEFAULT_PROVIDER=parallels
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY := YES

.PHONY: help bootstrap check-host verify-sources tools collections packer-init fetch-artifacts images image-linux image-windows \
	build-products ensure-running inventory up up-core up-full converge configure-control configure-dashboard-infra check-dashboard-infra configure-dashboard-source configure-dashboard-runtime enroll test status halt down destroy clean-generated

help: ## Show supported lab operations.
	@awk 'BEGIN {FS = ":.*## "; printf "Jobman local lab\n\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

bootstrap: check-host verify-sources ## Prepare host tools and ignored lab state.
	./scripts/init-state.sh
	$(MAKE) tools collections packer-init fetch-artifacts

check-host: ## Check architecture, Parallels, capacity, and required CLIs.
	./scripts/check-host.sh

verify-sources: ## Verify the Windows ISO and local product repositories.
	./scripts/verify-sources.sh

tools: ## Verify exact host-tool versions; prints the interactive Vagrant install command if absent.
	./scripts/check-tools.sh

collections: ## Install pinned Ansible collections locally under .lab.
	ANSIBLE_CONFIG=ansible/ansible.cfg ansible-galaxy collection install -r ansible/requirements.yml

packer-init: ## Install the pinned Packer Parallels plugin.
	PACKER_PLUGIN_PATH="$(CURDIR)/.lab/packer/plugins" packer init packer/

fetch-artifacts: ## Download and verify pinned guest source artifacts.
	./scripts/fetch-artifacts.sh

images: image-linux image-windows ## Download the pinned AlmaLinux box and build the Windows box.

image-linux: ## Download and verify the official AlmaLinux ARM64 Parallels box.
	./scripts/fetch-alma-box.sh

image-windows: ## Build the secret-free Windows 11 ARM64 Parallels/Vagrant base box.
	./scripts/build-windows-box.sh

build-products: ## Cross-build Jobman, Jobman Agent, and Jobman Control from sibling repos.
	./scripts/build-products.sh

ensure-running: ## Start or resume selected VMs and wait for Vagrant communicators.
	./scripts/vagrant-up.sh $(LAB_GROUP)

inventory: ensure-running ## Generate Ansible inventory from config/topology.yml and Vagrant SSH/WinRM data.
	LAB_GROUP=$(LAB_GROUP) ./scripts/generate-inventory.rb

up: up-full ## Create the full lab.

up-core: image-linux ## Create Linux core services and compute nodes.
	$(MAKE) LAB_GROUP=core converge

up-full: images ## Create the complete Linux and Windows topology.
	$(MAKE) LAB_GROUP=full converge

converge: build-products fetch-artifacts inventory ## Apply all guest configuration idempotently.
	ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook ansible/site.yml

configure-control: ## Create synthetic OIDC realm, namespace, memberships, stores, and targets.
	./scripts/configure-control.sh

enroll: ## Issue one-time lab enrollment tokens and enroll target agents.
	JOBMAN_LAB_GROUP=$(LAB_GROUP) ./scripts/enroll-agents.sh

test: ## Run network, mounts, SSH, Slurm, Control, and end-to-end Jobman checks.
	JOBMAN_LAB_GROUP=$(LAB_GROUP) ./scripts/test-lab.sh

status: ## Show Vagrant and Parallels status for lab VMs.
	$(VAGRANT_ENV) vagrant status
	prlctl list --all --output name,status | awk 'NR == 1 || $$1 ~ /^jobman-lab-/'

halt: ## Gracefully halt lab VMs while retaining state.
	$(VAGRANT_ENV) vagrant halt

down: halt ## Alias for halt.

destroy: ## Destroy only Vagrant-managed jobman-lab VMs after confirmation.
	./scripts/destroy-lab.sh

clean-generated: ## Remove regenerable artifacts, credentials, and caches after confirmation.
	./scripts/clean-generated.sh

configure-dashboard-infra: ## Add Dashboard DB TLS/roles and log-reader ACLs on three existing running VMs.
	./scripts/configure-dashboard-infra.sh

check-dashboard-infra: ## Verify Dashboard TLS/roles and cross-user NFS reader ACLs with disposable probes.
	./scripts/check-dashboard-infra.py

configure-dashboard-source: ## Prepare an isolated source using CONTROL_FIXTURE_BUILD (exact Linux ARM64 build directory).
	./scripts/configure-dashboard-source.sh "$(CONTROL_FIXTURE_BUILD)"

configure-dashboard-runtime: ## Install app/broker using DASHBOARD_BUILD (exact Linux ARM64 executables and web directory).
	./scripts/configure-dashboard-runtime.sh "$(DASHBOARD_BUILD)"
