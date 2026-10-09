# ---------- OCI API authentication ----------
variable "tenancy_ocid" {
  description = "Tenancy OCID (Profile > Tenancy)"
  type        = string
}

variable "user_ocid" {
  description = "Your user OCID (Profile > My profile)"
  type        = string
}

variable "fingerprint" {
  description = "Fingerprint of the API key you uploaded"
  type        = string
}

variable "private_key_path" {
  description = "Path to the API private key (.pem)"
  type        = string
  default     = "~/.oci/oci_api_key.pem"
}

variable "region" {
  description = "Home region"
  type        = string
  default     = "eu-frankfurt-1"
}

# ---------- Access ----------
variable "ssh_public_key_path" {
  description = "SSH public key installed on every VM"
  type        = string
  default     = "~/.ssh/oci_lab.pub"
}

variable "admin_cidr" {
  description = "Your current public IP as /32 (used only while allow_public_ssh = true)"
  type        = string
}

variable "allow_public_ssh" {
  description = "Bootstrap only. Set to false once WireGuard works."
  type        = bool
  default     = true
}

# ---------- WireGuard ----------
variable "wg_client_pubkey" {
  description = "Public key of your laptop/phone WireGuard client"
  type        = string
}

variable "wg_port" {
  description = "WireGuard UDP port"
  type        = number
  default     = 51820
}

# ---------- Cost guard ----------
variable "alert_email" {
  description = "Email that receives budget alerts"
  type        = string
}

# ---------- Placement ----------
variable "arm_ad_index" {
  description = "Availability domain for the ARM VM (0, 1 or 2). Change if you hit 'Out of capacity'."
  type        = number
  default     = 0
}

variable "amd_ad_index" {
  description = "Availability domain for the AMD micro VM. Must be the AD where VM.Standard.E2.1.Micro is offered."
  type        = number
  default     = 0
}

# ---------- Network ----------
variable "vcn_cidr" {
  type    = string
  default = "10.10.0.0/16"
}

variable "subnet_cidr" {
  type    = string
  default = "10.10.1.0/24"
}

variable "tunnel_port" {
  description = "TCP port where wstunnel accepts the WireGuard-over-TLS tunnel"
  type        = number
  default     = 443
}

variable "wstunnel_prefix" {
  description = "Secret HTTP upgrade path prefix for wstunnel (contents of ~/.wg-lab/wstunnel.secret). Empty = gateway built without wstunnel."
  type        = string
  default     = ""
  sensitive   = true
}

variable "wstunnel_version" {
  description = "wstunnel release installed on the gateway (verified against the release checksums)"
  type        = string
  default     = "11.0.0"
}
