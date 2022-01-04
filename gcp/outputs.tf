output "vm-group" {
  value = google_compute_instance_group.terraform-instance-group.id
}