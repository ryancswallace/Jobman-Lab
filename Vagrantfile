# frozen_string_literal: true

require "yaml"

root = File.expand_path(__dir__)
topology = YAML.safe_load(File.read(File.join(root, "config", "topology.yml")), aliases: false)
versions = YAML.safe_load(File.read(File.join(root, "config", "versions.yml")), aliases: false)
nodes = topology.fetch("nodes")
domain = topology.dig("lab", "domain")
selected_group = ENV.fetch("JOBMAN_LAB_GROUP", "full")
allowed_groups = selected_group == "core" ? ["core"] : ["core", "full"]

Vagrant.configure("2") do |config|
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.boot_timeout = 900
  config.ssh.keep_alive = true

  nodes.each do |short_name, node|
    next unless allowed_groups.include?(node.fetch("group"))

    config.vm.define short_name do |machine|
      windows = node.fetch("role") == "windows_workstation"
      # Vagrant's Windows hostname action accepts a NetBIOS computer name, not
      # an FQDN. DNS aliases for the isolated lab are managed by Ansible.
      machine.vm.hostname = windows ? short_name : "#{short_name}.#{domain}"
      machine.vm.network "private_network", ip: node.fetch("address"), name: "jobman-lab"

      if windows
        box_path = File.join(root, ".lab", "boxes", "windows-11-arm64-parallels.box")
        machine.vm.box = "jobman-lab/windows-11-arm64"
        machine.vm.box_url = "file://#{box_path}"
        machine.vm.communicator = "winrm"
        machine.winrm.host = "127.0.0.1"
        machine.winrm.username = "vagrant"
        machine.winrm.password = "vagrant"
        machine.winrm.port = 5986
        machine.winrm.transport = :ssl
        machine.winrm.basic_auth_only = true
        machine.winrm.ssl_peer_verification = false
        machine.winrm.timeout = 1800
      else
        machine.vm.box = versions.dig("images", "alma_box")
        machine.vm.box_version = versions.dig("images", "alma_box_version")
        machine.vm.box_architecture = versions.dig("images", "alma_box_architecture")
        machine.vm.provision "shell", path: "scripts/vagrant-linux-bootstrap.sh", args: [short_name]
      end

      machine.vm.provider "parallels" do |prl|
        prl.name = "jobman-lab-#{short_name}"
        prl.cpus = node.fetch("cpus")
        prl.memory = node.fetch("memory_mb")
        prl.linked_clone = true
        prl.update_guest_tools = false
        if node.key?("data_disk_mb")
          prl.customize "post-import", ["set", :id, "--device-add", "hdd", "--type", "expand", "--size", node.fetch("data_disk_mb").to_s]
        end
      end
    end
  end
end
