packer {
  required_version = "= 1.16.0"
  required_plugins {
    parallels = {
      version = "= 1.2.8"
      source  = "github.com/Parallels/parallels"
    }
    vagrant = {
      version = "= 1.1.6"
      source  = "github.com/hashicorp/vagrant"
    }
  }
}

variable "windows_iso" {
  type = string
}

variable "windows_iso_sha256" {
  type = string
}

source "parallels-iso" "windows11_arm64" {
  boot_command           = ["<enter>"]
  boot_wait              = "3s"
  communicator           = "winrm"
  cpus                   = 4
  disk_size              = 65536
  cd_files               = ["${path.root}/http/Autounattend.xml", "${path.root}/scripts/base.ps1", "${path.root}/scripts/winrm.ps1"]
  cd_label               = "OEMDRV"
  guest_os_type          = "win-11"
  iso_checksum           = "sha256:${var.windows_iso_sha256}"
  iso_url                = var.windows_iso
  memory                 = 8192
  output_directory       = "${path.root}/output-windows-11-arm64"
  parallels_tools_flavor = "win-arm"
  parallels_tools_mode   = "attach"
  shutdown_command       = "shutdown /s /t 10 /f /d p:4:1"
  vm_name                = "jobman-lab-windows-11-arm64-base"
  winrm_password         = "vagrant"
  winrm_insecure         = true
  winrm_port             = 5986
  winrm_timeout          = "2h"
  winrm_use_ssl          = true
  winrm_username         = "vagrant"
}

build {
  sources = ["source.parallels-iso.windows11_arm64"]

  provisioner "powershell" {
    script = "${path.root}/scripts/base.ps1"
  }

  provisioner "windows-restart" {
    restart_timeout = "20m"
  }

  provisioner "powershell" {
    pause_before = "30s"
    pause_after  = "15s"
    inline = [
      "$toolsService = Get-Service | Where-Object { $_.DisplayName -like 'Parallels Tools*' } | Select-Object -First 1",
      "if (-not $toolsService) { throw 'Parallels Tools service is not installed after restart' }",
      "if ($toolsService.Status -ne 'Running') { throw 'Parallels Tools service is not running after restart' }"
    ]
  }

  post-processor "vagrant" {
    architecture      = "arm64"
    output            = "${path.root}/../.lab/boxes/windows-11-arm64-parallels.box"
    provider_override = "parallels"
  }
}
