# =====================================================================
#  SOC Lab - Week 1: compartment, budget guard, network, 2 VMs
#  Everything here is Always Free-eligible.
#    core-arm : VM.Standard.A1.Flex 2 OCPU / 12 GB, 100 GB disk (Wazuh, n8n later)
#    wg-gw    : VM.Standard.E2.1.Micro, 50 GB disk (WireGuard gateway)
#  Leaves 50 GB of the 200 GB block allowance for the Week 3 honeypot.
# =====================================================================

# ---------- Compartment ----------
resource "oci_identity_compartment" "lab" {
  compartment_id = var.tenancy_ocid
  name           = "soc-lab"
  description    = "Honeypot-to-SOC lab (Always Free)"
  enable_delete  = true
}

locals {
  cid = oci_identity_compartment.lab.id
}

# ---------- Cost guard: alert on ANY real spend ----------
resource "oci_budget_budget" "guard" {
  compartment_id = var.tenancy_ocid
  display_name   = "free-tier-guard"
  amount         = 1
  reset_period   = "MONTHLY"
  target_type    = "COMPARTMENT"
  targets        = [var.tenancy_ocid]
}

resource "oci_budget_alert_rule" "any_spend" {
  budget_id      = oci_budget_budget.guard.id
  display_name   = "any-actual-spend"
  type           = "ACTUAL"
  threshold      = 1
  threshold_type = "PERCENTAGE"
  recipients     = var.alert_email
  message        = "OCI actual spend detected. Check for non-Always-Free resources now."
}

resource "oci_budget_alert_rule" "forecast" {
  budget_id      = oci_budget_budget.guard.id
  display_name   = "forecast-spend"
  type           = "FORECAST"
  threshold      = 100
  threshold_type = "PERCENTAGE"
  recipients     = var.alert_email
  message        = "OCI forecasts spend this month. Review resources."
}

# ---------- Lookups ----------
data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

data "oci_core_images" "ubuntu_arm" {
  compartment_id           = var.tenancy_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = "VM.Standard.A1.Flex"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
  filter {
    name   = "display_name"
    values = ["^Canonical-Ubuntu-24\\.04-aarch64-[0-9]"]
    regex  = true
  }
}

data "oci_core_images" "ubuntu_amd" {
  compartment_id           = var.tenancy_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = "VM.Standard.E2.1.Micro"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
  filter {
    name   = "display_name"
    values = ["^Canonical-Ubuntu-24\\.04-[0-9]"]
    regex  = true
  }
}

# ---------- Network ----------
resource "oci_core_vcn" "lab" {
  compartment_id = local.cid
  display_name   = "soc-lab-vcn"
  cidr_blocks    = [var.vcn_cidr]
  dns_label      = "soclab"
}

resource "oci_core_internet_gateway" "igw" {
  compartment_id = local.cid
  vcn_id         = oci_core_vcn.lab.id
  display_name   = "soc-lab-igw"
  enabled        = true
}

resource "oci_core_route_table" "public" {
  compartment_id = local.cid
  vcn_id         = oci_core_vcn.lab.id
  display_name   = "soc-lab-public-rt"
  route_rules {
    network_entity_id = oci_core_internet_gateway.igw.id
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
  }
}

# Baseline security list: egress only + path-MTU ICMP. No SSH from the internet.
resource "oci_core_security_list" "baseline" {
  compartment_id = local.cid
  vcn_id         = oci_core_vcn.lab.id
  display_name   = "soc-lab-baseline"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  ingress_security_rules {
    source   = "0.0.0.0/0"
    protocol = "1"
    icmp_options {
      type = 3
      code = 4
    }
  }

  ingress_security_rules {
    source   = var.vcn_cidr
    protocol = "1"
    icmp_options {
      type = 3
    }
  }
}

resource "oci_core_subnet" "core" {
  compartment_id             = local.cid
  vcn_id                     = oci_core_vcn.lab.id
  display_name               = "soc-lab-core"
  cidr_block                 = var.subnet_cidr
  dns_label                  = "core"
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.baseline.id]
  prohibit_public_ip_on_vnic = false
}

# ---------- NSG: WireGuard gateway ----------
resource "oci_core_network_security_group" "wg" {
  compartment_id = local.cid
  vcn_id         = oci_core_vcn.lab.id
  display_name   = "nsg-wireguard"
}


resource "oci_core_network_security_group_security_rule" "wg_bootstrap_ssh" {
  count                     = var.allow_public_ssh ? 1 : 0
  network_security_group_id = oci_core_network_security_group.wg.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = var.admin_cidr
  source_type               = "CIDR_BLOCK"
  description               = "Bootstrap SSH - remove after WireGuard works"
  tcp_options {
    destination_port_range {
      min = 22
      max = 22
    }
  }
}

# ---------- NSG: core VM (reachable only from inside the VCN / via VPN) ----------
resource "oci_core_network_security_group" "core" {
  compartment_id = local.cid
  vcn_id         = oci_core_vcn.lab.id
  display_name   = "nsg-core"
}

resource "oci_core_network_security_group_security_rule" "core_from_vcn" {
  network_security_group_id = oci_core_network_security_group.core.id
  direction                 = "INGRESS"
  protocol                  = "all"
  source                    = var.vcn_cidr
  source_type               = "CIDR_BLOCK"
  description               = "All traffic from inside the VCN (VPN clients are NATed by wg-gw)"
}

# ---------- Instances ----------
resource "oci_core_instance" "wg" {
  compartment_id      = local.cid
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[var.amd_ad_index].name
  display_name        = "wg-gw"
  shape               = "VM.Standard.E2.1.Micro"

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu_amd.images[0].id
    boot_volume_size_in_gbs = 50
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.core.id
    assign_public_ip = true
    hostname_label   = "wg-gw"
    nsg_ids          = [oci_core_network_security_group.wg.id]
  }

  metadata = {
    ssh_authorized_keys = file(pathexpand(var.ssh_public_key_path))
    user_data = base64encode(templatefile("${path.module}/cloud-init/wg-gw.sh.tftpl", {
      wg_port          = var.wg_port
      client_pubkey    = var.wg_client_pubkey
      tunnel_port      = var.tunnel_port
      wstunnel_prefix  = var.wstunnel_prefix
      wstunnel_version = var.wstunnel_version
    }))
  }

  lifecycle {
    ignore_changes = [source_details[0].source_id, metadata["user_data"]]
  }
}

resource "oci_core_instance" "core" {
  compartment_id      = local.cid
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[var.arm_ad_index].name
  display_name        = "core-arm"
  shape               = "VM.Standard.A1.Flex"

  shape_config {
    ocpus         = 2
    memory_in_gbs = 12
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu_arm.images[0].id
    boot_volume_size_in_gbs = 100
  }

  # Public IP for outbound updates and a future HTTPS site; NSG blocks all inbound from the internet.
  create_vnic_details {
    subnet_id        = oci_core_subnet.core.id
    assign_public_ip = true
    hostname_label   = "core-arm"
    nsg_ids          = [oci_core_network_security_group.core.id]
  }

  metadata = {
    ssh_authorized_keys = file(pathexpand(var.ssh_public_key_path))
    user_data           = base64encode(file("${path.module}/cloud-init/core-arm.sh"))
  }

  lifecycle {
    ignore_changes = [source_details[0].source_id, metadata["user_data"]]
  }
}

# WireGuard is wrapped in TLS over TCP (wstunnel), because the admin network
# path blocks outbound UDP. Only the admin egress IP may reach the tunnel.
resource "oci_core_network_security_group_security_rule" "wg_tunnel_tcp" {
  network_security_group_id = oci_core_network_security_group.wg.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = var.admin_cidr
  source_type               = "CIDR_BLOCK"
  description               = "wstunnel (WireGuard over TLS/TCP) from admin egress IP only"
  tcp_options {
    destination_port_range {
      min = var.tunnel_port
      max = var.tunnel_port
    }
  }
}
