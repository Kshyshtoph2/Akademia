terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
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