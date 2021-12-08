terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "3.5.0"
    }
  }
}

provider "google" {
  credentials = file("credentials.json")

  project = var.project_id
  region  = var.location["region"]
  zone    = var.location["zone"]
}

resource "google_compute_network" "vpc_network" {
  name = "terraform-network"
}


resource "google_compute_instance" "vm_instance" {
  name         = "terraform-instance"
  machine_type = "e2-small"

  boot_disk {
    initialize_params {
      image = "ubuntu-1804-bionic-v20211021"
    }
  }

  network_interface {
    network = google_compute_network.vpc_network.name
    access_config {
    }
  }

  metadata = {
    ssh-keys = "${var.user}:${file("${path.module}/public.pub")}"
  }

  provisioner "remote-exec" {
    connection {
      host        = google_compute_address.static.address
      type        = "ssh"
      user        = var.user
      timeout     = "500s"
      private_key = file("${path.module}/private.ppk")
    }
    inline = [
      "sudo yum -y install epel-release",
      "sudo yum -y install nginx",
      "sudo nginx -v",
    ]
  }
  depends_on = [
    google_compute_firewall.ingress, google_compute_firewall.egress, google_compute_address.static
  ]
}


resource "google_compute_firewall" "ingress" {
  name    = "test-firewall-ingress"
  network = google_compute_network.vpc_network.name

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "22"]
  }
  direction = "INGRESS"
}

resource "google_compute_address" "static" {
  name       = "vm-public-address"
  project    = var.project_id
  region     = var.location["region"]
  depends_on = [google_compute_firewall.ingress]
}


resource "google_compute_firewall" "egress" {
  name    = "test-firewall-egress"
  network = google_compute_network.vpc_network.name
  deny {
    protocol = "all"
  }
  direction = "EGRESS"
}

