variable "name" {
  type        = string
  description = "e.g. base-rocky9-20261116"
}
variable "distro" { type = string }
variable "node" { type = string }
variable "vm_id" { type = number }
variable "image_url" {
  type        = string
  description = "Official cloud image (qcow2), e.g. https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2"
}
variable "image_file_name" {
  type        = string
  description = "Name on Proxmox storage; must end in .qcow2 (content_type import) or .img (content_type iso)."
}
variable "checksum" {
  type        = string
  default     = null
  description = "The image's checksum from the distribution's CHECKSUM/SHA256SUMS file. Required unless allow_unverified_image."
}
variable "allow_unverified_image" {
  type        = bool
  default     = false
  description = "Import the image without a checksum: a tampered or truncated download goes unnoticed. Only for a base imported before checksums were required."
}
variable "checksum_algorithm" {
  type    = string
  default = "sha256"
}
variable "image_datastore" { type = string }
variable "image_content_type" {
  type        = string
  default     = "import"
  description = "\"import\" on Proxmox VE 8.4+; \"iso\" on older versions."
}
variable "datastore" { type = string }
variable "bridge" { type = string }
variable "disk_gib" {
  type    = number
  default = 10
}
