output "wg_gw_public_ip" {
  description = "Public IP of the gateway. Only the wstunnel port is reachable, and only from admin_cidr."
  value       = oci_core_instance.wg.public_ip
}

output "wg_gw_private_ip" {
  value = oci_core_instance.wg.private_ip
}

output "core_arm_private_ip" {
  value = oci_core_instance.core.private_ip
}

output "tunnel_endpoint" {
  description = "Where the Mac wstunnel client connects"
  value       = "wss://${oci_core_instance.wg.public_ip}:${var.tunnel_port}"
}

output "next_step" {
  value = var.allow_public_ssh ? "Bootstrap: ssh -i ~/.ssh/oci_lab ubuntu@${oci_core_instance.wg.public_ip} 'sudo cat /etc/wireguard/server.pub' > ~/.wg-lab/server.pub" : "Daily use: lab up  ->  ssh lab-gw (10.66.66.1)  |  ssh lab-core (${oci_core_instance.core.private_ip})  ->  lab down"
}
