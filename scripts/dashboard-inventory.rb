#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "json"
require "open3"
require "shellwords"
require "yaml"

root = File.expand_path("..", __dir__)
state = File.join(root, ".lab", "dashboard")
FileUtils.mkdir_p(state, mode: 0o700)
nodes = %w[pg01 storage01 control01]
prior_path = File.join(state, "vm-host-keys.json")
prior = File.exist?(prior_path) ? JSON.parse(File.read(prior_path)) : {}
identities = {}
hosts = {}
keys = []
nodes.each do |name|
  vm = "jobman-lab-#{name}"
  status, result = Open3.capture2e("prlctl", "status", vm)
  abort "#{vm} must already be running; this script never starts VMs" unless result.success? && status.match?(/\brunning\b/i)
  id = File.read(File.join(root, ".vagrant", "machines", name, "parallels", "id")).strip
  output, result = Open3.capture2e({"VAGRANT_DEFAULT_PROVIDER" => "parallels", "JOBMAN_LAB_GROUP" => "core"}, "vagrant", "ssh-config", name, chdir: root)
  abort "Cannot read #{name} Vagrant SSH endpoint" unless result.success?
  ssh = output.lines.map do |line|
    match = line.match(/^\s+(HostName|User|Port|IdentityFile)\s+(.+)$/)
    [match[1], Shellwords.split(match[2]).first] if match
  end.compact.to_h
  abort "Incomplete #{name} SSH endpoint" unless %w[HostName User Port IdentityFile].all? { |field| ssh.key?(field) }
  # Pin through the local hypervisor guest channel, not an unauthenticated scan.
  public_key, result = Open3.capture2e("prlctl", "exec", id, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
  abort "Cannot obtain #{name} VM-bound SSH public key" unless result.success?
  key = public_key.lines.map(&:strip).find { |line| line.match?(/^ssh-ed25519 [A-Za-z0-9+\/=]+(?:\s|$)/) }
  abort "Invalid #{name} Ed25519 host key" unless key
  key = key.split.take(2).join(" ")
  identities[name] = {"vm_id" => id, "host_key" => key}
  abort "#{name} VM identity or host key changed; review and repair the Dashboard inventory explicitly" if prior.key?(name) && prior[name] != identities[name]
  endpoint = ssh.fetch("Port") == "22" ? ssh.fetch("HostName") : "[#{ssh.fetch('HostName')}]:#{ssh.fetch('Port')}"
  keys << "#{endpoint} #{key}\n"
  hosts[name] = {"ansible_host" => ssh.fetch("HostName"), "ansible_user" => ssh.fetch("User"), "ansible_port" => ssh.fetch("Port").to_i, "ansible_ssh_private_key_file" => ssh.fetch("IdentityFile")}
end
inventory = {"all" => {"vars" => {"lab_root" => root}, "hosts" => hosts}}
File.write(File.join(state, "inventory.yml"), YAML.dump(inventory), mode: "w", perm: 0o600)
File.write(File.join(state, "known_hosts"), keys.join, mode: "w", perm: 0o600)
File.write(prior_path, JSON.generate(identities), mode: "w", perm: 0o600)
File.write(File.join(state, "ssh-connections.json"), JSON.generate(hosts), mode: "w", perm: 0o600)
puts "Dashboard inventory pins three existing VM identities; no VM power state changed."
