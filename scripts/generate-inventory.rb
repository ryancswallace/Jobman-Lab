#!/usr/bin/env ruby
# frozen_string_literal: true

require "open3"
require "shellwords"
require "yaml"

root = File.expand_path("..", __dir__)
topology = YAML.safe_load(File.read(File.join(root, "config", "topology.yml")), aliases: false)
group = ENV.fetch("LAB_GROUP", ENV.fetch("JOBMAN_LAB_GROUP", "full"))
selected_groups = group == "core" ? ["core"] : ["core", "full"]
nodes = topology.fetch("nodes").select { |_name, node| selected_groups.include?(node.fetch("group")) }

inventory = {
  "all" => {
    "vars" => {
      "lab_root" => root,
      "lab_domain" => topology.dig("lab", "domain"),
      "lab_namespace" => topology.dig("lab", "namespace"),
      "lab_network_cidr" => topology.dig("lab", "network", "cidr"),
      "lab_users" => topology.dig("lab", "users"),
      "lab_nodes" => nodes.transform_values { |node| node.slice("role", "address") },
      "lab_storage" => topology.fetch("storage")
    },
    "children" => {
      "linux" => { "hosts" => {} },
      "windows" => { "hosts" => {} }
    }
  }
}

role_groups = Hash.new { |hash, key| hash[key] = { "hosts" => {} } }
known_hosts = []

nodes.each do |name, node|
  role = node.fetch("role")
  if role == "windows_workstation"
    output, status = Open3.capture2e(
      { "JOBMAN_LAB_GROUP" => group, "VAGRANT_DEFAULT_PROVIDER" => "parallels" },
      "vagrant", "winrm-config", name, chdir: root
    )
    abort "cannot read Vagrant WinRM configuration for #{name}: #{output}" unless status.success?

    winrm = output.lines.map do |line|
      match = line.match(/^\s+(HostName|User|Password|Port)\s+(.+)$/)
      [match[1], Shellwords.split(match[2]).first] if match
    end.compact.to_h
    required = %w[HostName User Password Port]
    abort "incomplete Vagrant WinRM configuration for #{name}" unless required.all? { |key| winrm.key?(key) }

    host_vars = {
      "ansible_host" => winrm.fetch("HostName"),
      "ansible_connection" => "winrm",
      "ansible_user" => winrm.fetch("User"),
      "ansible_password" => winrm.fetch("Password"),
      "ansible_port" => winrm.fetch("Port").to_i,
      "ansible_winrm_scheme" => "https",
      "ansible_winrm_transport" => "basic",
      "ansible_winrm_server_cert_validation" => "ignore"
    }
    inventory.dig("all", "children", "windows", "hosts")[name] = host_vars
  else
    output, status = Open3.capture2e(
      { "JOBMAN_LAB_GROUP" => group, "VAGRANT_DEFAULT_PROVIDER" => "parallels" },
      "vagrant", "ssh-config", name, chdir: root
    )
    abort "cannot read Vagrant SSH configuration for #{name}: #{output}" unless status.success?

    ssh = output.lines.map do |line|
      match = line.match(/^\s+(HostName|User|Port|IdentityFile)\s+(.+)$/)
      [match[1], Shellwords.split(match[2]).first] if match
    end.compact.to_h
    required = %w[HostName User Port IdentityFile]
    abort "incomplete Vagrant SSH configuration for #{name}" unless required.all? { |key| ssh.key?(key) }

    host_vars = {
      "ansible_host" => ssh.fetch("HostName"),
      "ansible_user" => ssh.fetch("User"),
      "ansible_port" => ssh.fetch("Port").to_i,
      "ansible_ssh_private_key_file" => ssh.fetch("IdentityFile")
    }
    inventory.dig("all", "children", "linux", "hosts")[name] = host_vars

    keyscan, scan_status = Open3.capture2e(
      "ssh-keyscan", "-T", "10", "-p", ssh.fetch("Port"), ssh.fetch("HostName")
    )
    abort "cannot scan SSH host key for #{name}: #{keyscan}" unless scan_status.success?
    known_hosts.concat(keyscan.lines.reject { |line| line.start_with?("#") })
  end
  role_groups[role]["hosts"][name] = {}
end

inventory.dig("all", "children").merge!(role_groups)

inventory_path = File.join(root, "ansible", "inventory.generated.yml")
File.write(inventory_path, YAML.dump(inventory), mode: "w", perm: 0o600)
File.write(File.join(root, ".lab", "ssh", "known_hosts"), known_hosts.uniq.sort.join, mode: "w", perm: 0o600)
puts "generated #{inventory_path}"
