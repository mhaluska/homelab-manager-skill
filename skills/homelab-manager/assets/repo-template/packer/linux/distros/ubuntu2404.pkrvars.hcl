distro         = "ubuntu"
distro_version = "2404"
ssh_username   = "ubuntu"
# base image (dated, as in tfvars): https://cloud-images.ubuntu.com/noble/<YYYYMMDD>/noble-server-cloudimg-amd64.img
# (it is qcow2 despite the .img name — store it as *.qcow2 for content_type "import")
