# =====================================================================
#  SOC Lab - Week 3: Cowrie honeypot in its OWN VCN (Always Free)
#    honeypot : VM.Standard.E2.1.Micro, 50 GB disk, VCN 10.20.0.0/16
#
#  Isolation model ("pull, never push"):
#    - The honeypot has no route to accept from, and no rule that admits,
#      any connection INTO the lab: only the lab (core-arm) may open
#      connections to the honeypot, on the admin port, through a local
#      peering gateway. Replies flow back statefully.
#    - Bait ports (22 SSH, 23 Telnet) are opened to the internet ONLY when
#      var.honeypot_bait_enabled = true, i.e. after Cowrie runs and the
#      isolation has been tested.
#    - Outbound internet limited to DNS/HTTP/HTTPS (+ OCI instance services).
# =====================================================================

locals {
  core_admin_src = "${oci_core_instance.core.private_ip}/32"
}

# ---------- Network ----------
resource "oci_core_vcn" "hp" {
  compartment_id = local.cid
  display_name   = "soc-honeypot-vcn"
  cidr_blocks    = [var.hp_vcn_cidr]
  dns_label      = "hpnet"
}

resource "oci_core_internet_gateway" "hp" {
  compartment_id = local.cid
  vcn_id         = oci_core_vcn.hp.id
  display_name   = "soc-honeypot-igw"
  enabled        = true
}

# Local peering: lab <-> honeypot. Security rules (below and in main.tf) make
# it one-way for NEW connections: lab -> honeypot admin port only.
resource "oci_core_local_peering_gateway" "lab_to_hp" {
  compartment_id = local.cid
  vcn_id         = oci_core_vcn.lab.id
  display_name   = "lpg-lab-to-honeypot"
}

resource "oci_core_local_peering_gateway" "hp_to_lab" {
  compartment_id = local.cid
  vcn_id         = oci_core_vcn.hp.id
  display_name   = "lpg-honeypot-to-lab"
  peer_id        = oci_core_local_peering_gateway.lab_to_hp.id
}

resource "oci_core_route_table" "hp" {
  compartment_id = local.cid
  vcn_id         = oci_core_vcn.hp.id
  display_name   = "soc-honeypot-rt"
  route_rules {
    network_entity_id = oci_core_internet_gateway.hp.id
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
  }
  # Needed so REPLIES to lab-initiated sessions can return. New honeypot->lab
  # connections are still refused by the lab's rules and the honeypot's own firewall.
  route_rules {
    network_entity_id = oci_core_local_peering_gateway.hp_to_lab.id
    destination       = var.vcn_cidr
    destination_type  = "CIDR_BLOCK"
  }
}

# Subnet-level list: nothing in, nothing out, except path-MTU ICMP.
# All real rules live in the NSG so they are explicit and reviewable.
resource "oci_core_security_list" "hp" {
  compartment_id = local.cid
  vcn_id         = oci_core_vcn.hp.id
  display_name   = "soc-honeypot-baseline"

  ingress_security_rules {
    source   = "0.0.0.0/0"
    protocol = "1"
    icmp_options {
      type = 3
      code = 4
    }
  }
}

resource "oci_core_subnet" "hp" {
  compartment_id             = local.cid
  vcn_id                     = oci_core_vcn.hp.id
  display_name               = "soc-honeypot-subnet"
  cidr_block                 = var.hp_subnet_cidr
  dns_label                  = "edge"
  route_table_id             = oci_core_route_table.hp.id
  security_list_ids          = [oci_core_security_list.hp.id]
  prohibit_public_ip_on_vnic = false
}

# ---------- NSG: honeypot ----------
resource "oci_core_network_security_group" "hp" {
  compartment_id = local.cid
  vcn_id         = oci_core_vcn.hp.id
  display_name   = "nsg-honeypot"
}

# Real admin SSH: ONLY from core-arm (also the log puller; admins jump through it).
resource "oci_core_network_security_group_security_rule" "hp_admin_from_core" {
  network_security_group_id = oci_core_network_security_group.hp.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = local.core_admin_src
  source_type               = "CIDR_BLOCK"
  description               = "Real SSH (admin + read-only log pull) from core-arm only"
  tcp_options {
    destination_port_range {
      min = var.hp_admin_port
      max = var.hp_admin_port
    }
  }
}

# Bait: off until Cowrie runs and isolation is verified.
resource "oci_core_network_security_group_security_rule" "hp_bait" {
  for_each                  = var.honeypot_bait_enabled ? toset(["22", "23"]) : toset([])
  network_security_group_id = oci_core_network_security_group.hp.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "0.0.0.0/0"
  source_type               = "CIDR_BLOCK"
  description               = "Cowrie bait port ${each.key} from the internet"
  tcp_options {
    destination_port_range {
      min = tonumber(each.key)
      max = tonumber(each.key)
    }
  }
}

# Egress: only what Cowrie and the OS need.
resource "oci_core_network_security_group_security_rule" "hp_egress_tcp" {
  for_each                  = toset(["53", "80", "443"])
  network_security_group_id = oci_core_network_security_group.hp.id
  direction                 = "EGRESS"
  protocol                  = "6"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  description               = "Outbound TCP ${each.key} (DNS/updates/Cowrie download capture)"
  tcp_options {
    destination_port_range {
      min = tonumber(each.key)
      max = tonumber(each.key)
    }
  }
}

resource "oci_core_network_security_group_security_rule" "hp_egress_dns_udp" {
  network_security_group_id = oci_core_network_security_group.hp.id
  direction                 = "EGRESS"
  protocol                  = "17"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  description               = "Outbound DNS (UDP 53)"
  udp_options {
    destination_port_range {
      min = 53
      max = 53
    }
  }
}

resource "oci_core_network_security_group_security_rule" "hp_egress_instance_services" {
  network_security_group_id = oci_core_network_security_group.hp.id
  direction                 = "EGRESS"
  protocol                  = "all"
  destination               = "169.254.169.254/32"
  destination_type          = "CIDR_BLOCK"
  description               = "OCI instance services (metadata, DNS resolver, NTP)"
}

# ---------- Instance ----------
resource "oci_core_instance" "hp" {
  compartment_id      = local.cid
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[var.amd_ad_index].name
  display_name        = "hp-cowrie"
  shape               = "VM.Standard.E2.1.Micro"

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu_amd.images[0].id
    boot_volume_size_in_gbs = 50
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.hp.id
    assign_public_ip = true
    hostname_label   = "web01"
    nsg_ids          = [oci_core_network_security_group.hp.id]
  }

  # No secrets in user_data: it is readable from the instance metadata service.
  metadata = {
    ssh_authorized_keys = file(pathexpand(var.ssh_public_key_path))
    user_data = base64encode(templatefile("${path.module}/cloud-init/honeypot.sh.tftpl", {
      admin_port = var.hp_admin_port
      admin_src  = local.core_admin_src
      lab_cidr   = var.vcn_cidr
    }))
  }

  lifecycle {
    ignore_changes = [source_details[0].source_id, metadata["user_data"]]
  }
}
