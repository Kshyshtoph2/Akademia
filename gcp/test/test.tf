resource "google_project" "infra_actor_333516" {
  auto_create_network = true
  billing_account     = "018D57-618826-1D1FC9"
  name                = "My First Project"
  project_id          = "infra-actor-333516"
}
# terraform import google_project.infra_actor_333516 projects/infra-actor-333516
resource "google_compute_address" "nat_auto_ip_1779784_8_1641304357129320" {
  address      = "34.118.111.36"
  address_type = "EXTERNAL"
  name         = "nat-auto-ip-1779784-8-1641304357129320"
  network_tier = "PREMIUM"
  project      = "infra-actor-333516"
  purpose      = "NAT_AUTO"
  region       = "europe-central2"
}
# terraform import google_compute_address.nat_auto_ip_1779784_8_1641304357129320 projects/infra-actor-333516/regions/europe-central2/addresses/nat-auto-ip-1779784-8-1641304357129320
resource "google_compute_address" "vm_public_address" {
  address      = "34.116.139.160"
  address_type = "EXTERNAL"
  name         = "vm-public-address"
  network_tier = "PREMIUM"
  project      = "infra-actor-333516"
  region       = "europe-central2"
}
# terraform import google_compute_address.vm_public_address projects/infra-actor-333516/regions/europe-central2/addresses/vm-public-address
resource "google_compute_backend_service" "terraform_backend" {
  connection_draining_timeout_sec = 300
  health_checks                   = ["https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/healthChecks/terraform-health-check"]
  load_balancing_scheme           = "EXTERNAL"
  name                            = "terraform-backend"
  port_name                       = "http"
  project                         = "infra-actor-333516"
  protocol                        = "HTTP"
  session_affinity                = "NONE"
  timeout_sec                     = 30
}
# terraform import google_compute_backend_service.terraform_backend projects/infra-actor-333516/global/backendServices/terraform-backend
resource "google_compute_disk" "terraform_instance" {
  image                     = "https://www.googleapis.com/compute/beta/projects/ubuntu-os-cloud/global/images/ubuntu-1804-bionic-v20211021"
  name                      = "terraform-instance"
  physical_block_size_bytes = 4096
  project                   = "infra-actor-333516"
  size                      = 10
  type                      = "pd-standard"
  zone                      = "europe-central2-a"
}
# terraform import google_compute_disk.terraform_instance projects/infra-actor-333516/zones/europe-central2-a/disks/terraform-instance
resource "google_compute_firewall" "default_allow_icmp" {
  allow {
    protocol = "icmp"
  }
  description   = "Allow ICMP from anywhere"
  direction     = "INGRESS"
  name          = "default-allow-icmp"
  network       = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  priority      = 65534
  project       = "infra-actor-333516"
  source_ranges = ["0.0.0.0/0"]
}
# terraform import google_compute_firewall.default_allow_icmp projects/infra-actor-333516/global/firewalls/default-allow-icmp
resource "google_compute_firewall" "default_allow_internal" {
  allow {
    ports    = ["0-65535"]
    protocol = "tcp"
  }
  allow {
    ports    = ["0-65535"]
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }
  description   = "Allow internal traffic on the default network"
  direction     = "INGRESS"
  name          = "default-allow-internal"
  network       = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  priority      = 65534
  project       = "infra-actor-333516"
  source_ranges = ["10.128.0.0/9"]
}
# terraform import google_compute_firewall.default_allow_internal projects/infra-actor-333516/global/firewalls/default-allow-internal
resource "google_compute_firewall" "default_allow_rdp" {
  allow {
    ports    = ["3389"]
    protocol = "tcp"
  }
  description   = "Allow RDP from anywhere"
  direction     = "INGRESS"
  name          = "default-allow-rdp"
  network       = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  priority      = 65534
  project       = "infra-actor-333516"
  source_ranges = ["0.0.0.0/0"]
}
# terraform import google_compute_firewall.default_allow_rdp projects/infra-actor-333516/global/firewalls/default-allow-rdp
resource "google_compute_firewall" "default_allow_ssh" {
  allow {
    ports    = ["22"]
    protocol = "tcp"
  }
  description   = "Allow SSH from anywhere"
  direction     = "INGRESS"
  name          = "default-allow-ssh"
  network       = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  priority      = 65534
  project       = "infra-actor-333516"
  source_ranges = ["0.0.0.0/0"]
}
# terraform import google_compute_firewall.default_allow_ssh projects/infra-actor-333516/global/firewalls/default-allow-ssh
resource "google_compute_firewall" "firewall_ingress" {
  allow {
    ports    = ["80", "443", "22"]
    protocol = "tcp"
  }
  allow {
    protocol = "icmp"
  }
  direction     = "INGRESS"
  name          = "firewall-ingress"
  network       = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/terraform-network"
  priority      = 1000
  project       = "infra-actor-333516"
  source_ranges = ["0.0.0.0/0"]
}
# terraform import google_compute_firewall.firewall_ingress projects/infra-actor-333516/global/firewalls/firewall-ingress
resource "google_compute_global_forwarding_rule" "https" {
  ip_address            = "34.117.187.19"
  ip_protocol           = "TCP"
  ip_version            = "IPV4"
  load_balancing_scheme = "EXTERNAL"
  name                  = "https"
  port_range            = "443-443"
  project               = "infra-actor-333516"
  target                = "https://www.googleapis.com/compute/beta/projects/infra-actor-333516/global/targetHttpsProxies/terraform-load-balancer-target-proxy-2"
}
# terraform import google_compute_global_forwarding_rule.https projects/infra-actor-333516/global/forwardingRules/https
resource "google_compute_global_forwarding_rule" "terraform_load_balancer_forwarding_rule" {
  ip_address            = "34.149.180.249"
  ip_protocol           = "TCP"
  ip_version            = "IPV4"
  load_balancing_scheme = "EXTERNAL"
  name                  = "terraform-load-balancer-forwarding-rule"
  port_range            = "80-80"
  project               = "infra-actor-333516"
  target                = "https://www.googleapis.com/compute/beta/projects/infra-actor-333516/global/targetHttpProxies/terraform-load-balancer-target-proxy"
}
# terraform import google_compute_global_forwarding_rule.terraform_load_balancer_forwarding_rule projects/infra-actor-333516/global/forwardingRules/terraform-load-balancer-forwarding-rule
resource "google_compute_health_check" "terraform_health_check" {
  check_interval_sec = 5
  healthy_threshold  = 2
  name               = "terraform-health-check"
  project            = "infra-actor-333516"
  tcp_health_check {
    port         = 80
    proxy_header = "NONE"
  }
  timeout_sec         = 5
  unhealthy_threshold = 2
}
# terraform import google_compute_health_check.terraform_health_check projects/infra-actor-333516/global/healthChecks/terraform-health-check
resource "google_compute_instance" "terraform_instance" {
  boot_disk {
    auto_delete = true
    device_name = "persistent-disk-0"
    initialize_params {
      image = "https://www.googleapis.com/compute/beta/projects/ubuntu-os-cloud/global/images/ubuntu-1804-bionic-v20211021"
      size  = 10
      type  = "pd-standard"
    }
    mode   = "READ_WRITE"
    source = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/zones/europe-central2-a/disks/terraform-instance"
  }
  machine_type            = "e2-small"
  metadata_startup_script = "#!/bin/bash\n\nsudo apt update -y\nsudo apt install -y nginx\nCONF=$(cat <<- END \nevents {\n    worker_connections 1024;\n}\n\nhttp {\n\n    server {\n        listen 80;\n        \n        location / {\n            root /www/data;\n        }\n    }\n}\nEND\n)\necho \"$CONF\" | sudo tee /etc/nginx/nginx.conf\nsudo mkdir /www \nsudo mkdir /www/data \nINDEX=$(cat <<- END\n<!doctype html>\n<html>\n  <head>\n    <title>Hello nginx</title>\n    <meta charset=\"utf-8\" />\n  </head>\n  <body>\n    <h1>\n      Hello World!\n    </h1>\n  </body>\n</html>\nEND\n)\necho \"$INDEX\" | sudo tee /www/data/index.html\nsudo service nginx restart"
  name                    = "terraform-instance"
  network_interface {
    network            = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/terraform-network"
    network_ip         = "10.0.0.2"
    stack_type         = "IPV4_ONLY"
    subnetwork         = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/regions/europe-central2/subnetworks/terraform-subnet"
    subnetwork_project = "infra-actor-333516"
  }
  project = "infra-actor-333516"
  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }
  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_vtpm                 = true
  }
  zone = "europe-central2-a"
}
# terraform import google_compute_instance.terraform_instance projects/infra-actor-333516/zones/europe-central2-a/instances/terraform-instance
resource "google_compute_instance_group" "terraform_instance_group" {
  instances = ["https://www.googleapis.com/compute/beta/projects/infra-actor-333516/zones/europe-central2-a/instances/terraform-instance"]
  name      = "terraform-instance-group"
  named_port {
    name = "http"
    port = 80
  }
  network = "https://www.googleapis.com/compute/beta/projects/infra-actor-333516/global/networks/terraform-network"
  project = "infra-actor-333516"
  zone    = "europe-central2-a"
}
# terraform import google_compute_instance_group.terraform_instance_group projects/infra-actor-333516/zones/europe-central2-a/instanceGroups/terraform-instance-group
resource "google_compute_network" "default" {
  auto_create_subnetworks = true
  description             = "Default network for the project"
  name                    = "default"
  project                 = "infra-actor-333516"
  routing_mode            = "REGIONAL"
}
# terraform import google_compute_network.default projects/infra-actor-333516/global/networks/default
resource "google_compute_route" "default_route_0e11361590c1271b" {
  description = "Default local route to the subnetwork 10.178.0.0/20."
  dest_range  = "10.178.0.0/20"
  name        = "default-route-0e11361590c1271b"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_0e11361590c1271b projects/infra-actor-333516/global/routes/default-route-0e11361590c1271b
resource "google_compute_network" "terraform_network" {
  name         = "terraform-network"
  project      = "infra-actor-333516"
  routing_mode = "REGIONAL"
}
# terraform import google_compute_network.terraform_network projects/infra-actor-333516/global/networks/terraform-network
resource "google_compute_route" "default_route_25e064752cf510e3" {
  description = "Default local route to the subnetwork 10.166.0.0/20."
  dest_range  = "10.166.0.0/20"
  name        = "default-route-25e064752cf510e3"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_25e064752cf510e3 projects/infra-actor-333516/global/routes/default-route-25e064752cf510e3
resource "google_compute_route" "default_route_069155dafbde34dc" {
  description = "Default local route to the subnetwork 10.174.0.0/20."
  dest_range  = "10.174.0.0/20"
  name        = "default-route-069155dafbde34dc"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_069155dafbde34dc projects/infra-actor-333516/global/routes/default-route-069155dafbde34dc
resource "google_compute_route" "default_route_293a92fd51deb74b" {
  description = "Default local route to the subnetwork 10.170.0.0/20."
  dest_range  = "10.170.0.0/20"
  name        = "default-route-293a92fd51deb74b"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_293a92fd51deb74b projects/infra-actor-333516/global/routes/default-route-293a92fd51deb74b
resource "google_compute_route" "default_route_1b7231c21640d165" {
  description = "Default local route to the subnetwork 10.158.0.0/20."
  dest_range  = "10.158.0.0/20"
  name        = "default-route-1b7231c21640d165"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_1b7231c21640d165 projects/infra-actor-333516/global/routes/default-route-1b7231c21640d165
resource "google_compute_route" "default_route_25a4087d700ba256" {
  description = "Default local route to the subnetwork 10.186.0.0/20."
  dest_range  = "10.186.0.0/20"
  name        = "default-route-25a4087d700ba256"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_25a4087d700ba256 projects/infra-actor-333516/global/routes/default-route-25a4087d700ba256
resource "google_compute_route" "default_route_18ac3f71f0c683ef" {
  description = "Default local route to the subnetwork 10.154.0.0/20."
  dest_range  = "10.154.0.0/20"
  name        = "default-route-18ac3f71f0c683ef"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_18ac3f71f0c683ef projects/infra-actor-333516/global/routes/default-route-18ac3f71f0c683ef
resource "google_compute_route" "default_route_2f42273ea592c957" {
  description = "Default local route to the subnetwork 10.188.0.0/20."
  dest_range  = "10.188.0.0/20"
  name        = "default-route-2f42273ea592c957"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_2f42273ea592c957 projects/infra-actor-333516/global/routes/default-route-2f42273ea592c957
resource "google_compute_route" "default_route_47db233d7b61afe4" {
  description = "Default local route to the subnetwork 10.172.0.0/20."
  dest_range  = "10.172.0.0/20"
  name        = "default-route-47db233d7b61afe4"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_47db233d7b61afe4 projects/infra-actor-333516/global/routes/default-route-47db233d7b61afe4
resource "google_compute_route" "default_route_3e072f28d2d9ecb8" {
  description = "Default local route to the subnetwork 10.0.0.0/22."
  dest_range  = "10.0.0.0/22"
  name        = "default-route-3e072f28d2d9ecb8"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/terraform-network"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_3e072f28d2d9ecb8 projects/infra-actor-333516/global/routes/default-route-3e072f28d2d9ecb8
resource "google_compute_route" "default_route_646da83818f3afe0" {
  description = "Default local route to the subnetwork 10.138.0.0/20."
  dest_range  = "10.138.0.0/20"
  name        = "default-route-646da83818f3afe0"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_646da83818f3afe0 projects/infra-actor-333516/global/routes/default-route-646da83818f3afe0
resource "google_compute_route" "default_route_8854347d3ea0a567" {
  description = "Default local route to the subnetwork 10.162.0.0/20."
  dest_range  = "10.162.0.0/20"
  name        = "default-route-8854347d3ea0a567"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_8854347d3ea0a567 projects/infra-actor-333516/global/routes/default-route-8854347d3ea0a567
resource "google_compute_route" "default_route_668478b52dc6a88a" {
  description = "Default local route to the subnetwork 10.142.0.0/20."
  dest_range  = "10.142.0.0/20"
  name        = "default-route-668478b52dc6a88a"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_668478b52dc6a88a projects/infra-actor-333516/global/routes/default-route-668478b52dc6a88a
resource "google_compute_route" "default_route_9038e9afab49c65d" {
  description = "Default local route to the subnetwork 10.146.0.0/20."
  dest_range  = "10.146.0.0/20"
  name        = "default-route-9038e9afab49c65d"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_9038e9afab49c65d projects/infra-actor-333516/global/routes/default-route-9038e9afab49c65d
resource "google_compute_route" "default_route_9aed419e13debc51" {
  description = "Default local route to the subnetwork 10.192.0.0/20."
  dest_range  = "10.192.0.0/20"
  name        = "default-route-9aed419e13debc51"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_9aed419e13debc51 projects/infra-actor-333516/global/routes/default-route-9aed419e13debc51
resource "google_compute_route" "default_route_813c4b33e5875925" {
  description = "Default local route to the subnetwork 10.180.0.0/20."
  dest_range  = "10.180.0.0/20"
  name        = "default-route-813c4b33e5875925"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_813c4b33e5875925 projects/infra-actor-333516/global/routes/default-route-813c4b33e5875925
resource "google_compute_route" "default_route_ba144f20743c1392" {
  description = "Default local route to the subnetwork 10.194.0.0/20."
  dest_range  = "10.194.0.0/20"
  name        = "default-route-ba144f20743c1392"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_ba144f20743c1392 projects/infra-actor-333516/global/routes/default-route-ba144f20743c1392
resource "google_compute_route" "default_route_c3fc36d42e6788ae" {
  description = "Default local route to the subnetwork 10.150.0.0/20."
  dest_range  = "10.150.0.0/20"
  name        = "default-route-c3fc36d42e6788ae"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_c3fc36d42e6788ae projects/infra-actor-333516/global/routes/default-route-c3fc36d42e6788ae
resource "google_compute_route" "default_route_eb13dd02820dc71d" {
  description = "Default local route to the subnetwork 10.160.0.0/20."
  dest_range  = "10.160.0.0/20"
  name        = "default-route-eb13dd02820dc71d"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_eb13dd02820dc71d projects/infra-actor-333516/global/routes/default-route-eb13dd02820dc71d
resource "google_compute_route" "default_route_a8aea384e5d35d39" {
  description = "Default local route to the subnetwork 10.132.0.0/20."
  dest_range  = "10.132.0.0/20"
  name        = "default-route-a8aea384e5d35d39"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_a8aea384e5d35d39 projects/infra-actor-333516/global/routes/default-route-a8aea384e5d35d39
resource "google_compute_route" "default_route_29f8da3df768f9b3" {
  description = "Default local route to the subnetwork 10.148.0.0/20."
  dest_range  = "10.148.0.0/20"
  name        = "default-route-29f8da3df768f9b3"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_29f8da3df768f9b3 projects/infra-actor-333516/global/routes/default-route-29f8da3df768f9b3
resource "google_compute_route" "default_route_7d5031f645f61d79" {
  description      = "Default route to the Internet."
  dest_range       = "0.0.0.0/0"
  name             = "default-route-7d5031f645f61d79"
  network          = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  next_hop_gateway = "https://www.googleapis.com/compute/beta/projects/infra-actor-333516/global/gateways/default-internet-gateway"
  priority         = 1000
  project          = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_7d5031f645f61d79 projects/infra-actor-333516/global/routes/default-route-7d5031f645f61d79
resource "google_compute_route" "default_route_dfb46fe7c045c1fa" {
  description = "Default local route to the subnetwork 10.156.0.0/20."
  dest_range  = "10.156.0.0/20"
  name        = "default-route-dfb46fe7c045c1fa"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_dfb46fe7c045c1fa projects/infra-actor-333516/global/routes/default-route-dfb46fe7c045c1fa
resource "google_compute_route" "default_route_edffd906dccba55f" {
  description = "Default local route to the subnetwork 10.152.0.0/20."
  dest_range  = "10.152.0.0/20"
  name        = "default-route-edffd906dccba55f"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_edffd906dccba55f projects/infra-actor-333516/global/routes/default-route-edffd906dccba55f
resource "google_compute_route" "default_route_c577ab0c08810c37" {
  description = "Default local route to the subnetwork 10.182.0.0/20."
  dest_range  = "10.182.0.0/20"
  name        = "default-route-c577ab0c08810c37"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_c577ab0c08810c37 projects/infra-actor-333516/global/routes/default-route-c577ab0c08810c37
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.178.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "asia-northeast3"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/asia-northeast3/subnetworks/default
resource "google_compute_route" "default_route_c768f0ce44bf6af3" {
  description = "Default local route to the subnetwork 10.196.0.0/20."
  dest_range  = "10.196.0.0/20"
  name        = "default-route-c768f0ce44bf6af3"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_c768f0ce44bf6af3 projects/infra-actor-333516/global/routes/default-route-c768f0ce44bf6af3
resource "google_compute_route" "default_route_ed26298721b2b999" {
  description = "Default local route to the subnetwork 10.128.0.0/20."
  dest_range  = "10.128.0.0/20"
  name        = "default-route-ed26298721b2b999"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_ed26298721b2b999 projects/infra-actor-333516/global/routes/default-route-ed26298721b2b999
resource "google_compute_route" "default_route_ecc3ff46d5bf0333" {
  description = "Default local route to the subnetwork 10.190.0.0/20."
  dest_range  = "10.190.0.0/20"
  name        = "default-route-ecc3ff46d5bf0333"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_ecc3ff46d5bf0333 projects/infra-actor-333516/global/routes/default-route-ecc3ff46d5bf0333
resource "google_compute_route" "default_route_cd692837c4f0b107" {
  description = "Default local route to the subnetwork 10.184.0.0/20."
  dest_range  = "10.184.0.0/20"
  name        = "default-route-cd692837c4f0b107"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_cd692837c4f0b107 projects/infra-actor-333516/global/routes/default-route-cd692837c4f0b107
resource "google_compute_route" "default_route_fdf11693b9ad003d" {
  description = "Default local route to the subnetwork 10.168.0.0/20."
  dest_range  = "10.168.0.0/20"
  name        = "default-route-fdf11693b9ad003d"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_fdf11693b9ad003d projects/infra-actor-333516/global/routes/default-route-fdf11693b9ad003d
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.148.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "asia-southeast1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/asia-southeast1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.170.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "asia-east2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/asia-east2/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.190.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "asia-south2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/asia-south2/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.186.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "europe-central2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/europe-central2/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.140.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "asia-east1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/asia-east1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.152.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "australia-southeast1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/australia-southeast1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.154.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "europe-west2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/europe-west2/subnetworks/default
resource "google_compute_route" "default_route_f22e4ddc59a653f5" {
  description = "Default local route to the subnetwork 10.164.0.0/20."
  dest_range  = "10.164.0.0/20"
  name        = "default-route-f22e4ddc59a653f5"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_f22e4ddc59a653f5 projects/infra-actor-333516/global/routes/default-route-f22e4ddc59a653f5
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.192.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "australia-southeast2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/australia-southeast2/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.158.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "southamerica-east1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/southamerica-east1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.172.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "europe-west6"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/europe-west6/subnetworks/default
resource "google_compute_subnetwork" "terraform_subnet" {
  ip_cidr_range              = "10.0.0.0/22"
  name                       = "terraform-subnet"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/terraform-network"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "europe-central2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.terraform_subnet projects/infra-actor-333516/regions/europe-central2/subnetworks/terraform-subnet
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.156.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "europe-west3"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/europe-west3/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.132.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "europe-west1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/europe-west1/subnetworks/default
resource "google_compute_router" "terraform_nat_router" {
  name    = "terraform-nat-router"
  network = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/terraform-network"
  project = "infra-actor-333516"
  region  = "europe-central2"
}
# terraform import google_compute_router.terraform_nat_router projects/infra-actor-333516/regions/europe-central2/routers/terraform-nat-router
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.174.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "asia-northeast2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/asia-northeast2/subnetworks/default
resource "google_compute_ssl_certificate" "terraform_cert" {
  certificate = "-----BEGIN CERTIFICATE-----\nMIIEJzCCAw+gAwIBAgIUdHO7pFKnRv8oQbfecVDMFgFGh38wDQYJKoZIhvcNAQEL\nBQAwgaIxCzAJBgNVBAYTAlBMMRMwEQYDVQQIDApNYWxvcG9sc2thMQ8wDQYDVQQH\nDAZLcmFrb3cxGDAWBgNVBAoMD1NvbGlkIFBvdGVudGlhbDEMMAoGA1UECwwDZGV2\nMRIwEAYDVQQDDAlLcnp5c3p0b2YxMTAvBgkqhkiG9w0BCQEWImtyenlzenRvZi5i\nYXVtQHNvbGlkLXBvdGVudGlhbC5kZXYwHhcNMjIwMTA0MTQxMDM4WhcNMzIwMTAy\nMTQxMDM4WjCBojELMAkGA1UEBhMCUEwxEzARBgNVBAgMCk1hbG9wb2xza2ExDzAN\nBgNVBAcMBktyYWtvdzEYMBYGA1UECgwPU29saWQgUG90ZW50aWFsMQwwCgYDVQQL\nDANkZXYxEjAQBgNVBAMMCUtyenlzenRvZjExMC8GCSqGSIb3DQEJARYia3J6eXN6\ndG9mLmJhdW1Ac29saWQtcG90ZW50aWFsLmRldjCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAKwZs9FmhsY2yXoyjT0D/ZMkqGZAkxl5gI+7qPWlVrqMxr+V\nmj/KA4pQlZHYeL0yK3cThwTgV5OIgmJR5BQOs+3O7m7xIpHK0MfXLNoXaD78ZLvb\nngKjcmN8OWgyOjAkrr+M3Sd9yprwxxW1Cwuw4TRdGbQ7u4UaHuX7QnTk1dRILlTG\nxYrLhJokAOqahGx2y8E5t/kL82WDn/DWp04E7ZXe4NnZXnQVm1xEpQNzst1M6q/B\nXpV9vNR1WcBOvSSUkkFMormkEVSAEmf6faNvv3JPqwDbJ31ywqJVJB0gj9igGRRG\n/J+vZam0av53/1EzA3e4RNGsSLw/g/pp99Xu2ssCAwEAAaNTMFEwHQYDVR0OBBYE\nFL4X/hb2JY7k+gUbgpyYP74Yd10dMB8GA1UdIwQYMBaAFL4X/hb2JY7k+gUbgpyY\nP74Yd10dMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBACRAd0PL\n7FWNwai7zFXo7VCv38eHKSTREJO0EGcr/hJ/l4MY3YPfoZwrNqSL6Q+esuCVfqn4\nQFMDwGY8IB3JKcTT/RlEaDK7iwZYeEWfHOTuyyjESYDXvqIUkQLeyyjUhJiE4oVJ\n7d35S/p1UXUU1UO9gHhrcF+qSV2JRxZRK2XAYkJ/fi/WfGHl7mO9KDpIxlgQyN4o\nPWJwUPbrc7iDGuqLiAVX7/5Fx+AFxLmdou2mqL9FiTHbxEQluyrIKP7PkQKEnx7Q\n8gK3O1GKDvO3jnYyWoWOkhg6iJRewMPxWvSjBJelAWYXAimr6vKT3GdWR+NTq4lP\nik9mFGTx92fECp8=\n-----END CERTIFICATE-----\n"
  name        = "terraform-cert"
  project     = "infra-actor-333516"
}
# terraform import google_compute_ssl_certificate.terraform_cert projects/infra-actor-333516/global/sslCertificates/terraform-cert
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.146.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "asia-northeast1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/asia-northeast1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.138.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "us-west1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/us-west1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.194.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "southamerica-west1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/southamerica-west1/subnetworks/default
resource "google_compute_route" "default_route_ba977bdfdb00f710" {
  description      = "Default route to the Internet."
  dest_range       = "0.0.0.0/0"
  name             = "default-route-ba977bdfdb00f710"
  network          = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/terraform-network"
  next_hop_gateway = "https://www.googleapis.com/compute/beta/projects/infra-actor-333516/global/gateways/default-internet-gateway"
  priority         = 1000
  project          = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_ba977bdfdb00f710 projects/infra-actor-333516/global/routes/default-route-ba977bdfdb00f710
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.128.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "us-central1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/us-central1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.160.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "asia-south1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/asia-south1/subnetworks/default
resource "google_compute_route" "default_route_f50552b8ee3e5f7b" {
  description = "Default local route to the subnetwork 10.140.0.0/20."
  dest_range  = "10.140.0.0/20"
  name        = "default-route-f50552b8ee3e5f7b"
  network     = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  project     = "infra-actor-333516"
}
# terraform import google_compute_route.default_route_f50552b8ee3e5f7b projects/infra-actor-333516/global/routes/default-route-f50552b8ee3e5f7b
resource "google_project_service" "cloudapis_googleapis_com" {
  project = "937596446936"
  service = "cloudapis.googleapis.com"
}
# terraform import google_project_service.cloudapis_googleapis_com 937596446936/cloudapis.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.162.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "northamerica-northeast1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/northamerica-northeast1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.142.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "us-east1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/us-east1/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.150.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "us-east4"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/us-east4/subnetworks/default
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.180.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "us-west3"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/us-west3/subnetworks/default
resource "google_project_service" "logging_googleapis_com" {
  project = "937596446936"
  service = "logging.googleapis.com"
}
# terraform import google_project_service.logging_googleapis_com 937596446936/logging.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.168.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "us-west2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/us-west2/subnetworks/default
resource "google_compute_target_http_proxy" "terraform_load_balancer_target_proxy" {
  name    = "terraform-load-balancer-target-proxy"
  project = "infra-actor-333516"
  url_map = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/urlMaps/terraform-load-balancer"
}
# terraform import google_compute_target_http_proxy.terraform_load_balancer_target_proxy projects/infra-actor-333516/global/targetHttpProxies/terraform-load-balancer-target-proxy
resource "google_project_service" "storage_api_googleapis_com" {
  project = "937596446936"
  service = "storage-api.googleapis.com"
}
# terraform import google_project_service.storage_api_googleapis_com 937596446936/storage-api.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.166.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "europe-north1"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/europe-north1/subnetworks/default
resource "google_project_service" "sql_component_googleapis_com" {
  project = "937596446936"
  service = "sql-component.googleapis.com"
}
# terraform import google_project_service.sql_component_googleapis_com 937596446936/sql-component.googleapis.com
resource "google_project_service" "cloudasset_googleapis_com" {
  project = "937596446936"
  service = "cloudasset.googleapis.com"
}
# terraform import google_project_service.cloudasset_googleapis_com 937596446936/cloudasset.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.182.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "us-west4"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/us-west4/subnetworks/default
resource "google_project_service" "bigquery_googleapis_com" {
  project = "937596446936"
  service = "bigquery.googleapis.com"
}
# terraform import google_project_service.bigquery_googleapis_com 937596446936/bigquery.googleapis.com
resource "google_service_account" "terraform" {
  account_id   = "terraform"
  display_name = "Terraform"
  project      = "infra-actor-333516"
}
# terraform import google_service_account.terraform projects/infra-actor-333516/serviceAccounts/terraform@infra-actor-333516.iam.gserviceaccount.com
resource "google_project_service" "cloudtrace_googleapis_com" {
  project = "937596446936"
  service = "cloudtrace.googleapis.com"
}
# terraform import google_project_service.cloudtrace_googleapis_com 937596446936/cloudtrace.googleapis.com
resource "google_compute_target_https_proxy" "terraform_load_balancer_target_proxy_2" {
  name             = "terraform-load-balancer-target-proxy-2"
  project          = "infra-actor-333516"
  quic_override    = "NONE"
  ssl_certificates = ["https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/sslCertificates/terraform-cert"]
  url_map          = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/urlMaps/terraform-load-balancer"
}
# terraform import google_compute_target_https_proxy.terraform_load_balancer_target_proxy_2 projects/infra-actor-333516/global/targetHttpsProxies/terraform-load-balancer-target-proxy-2
resource "google_project_service" "compute_googleapis_com" {
  project = "937596446936"
  service = "compute.googleapis.com"
}
# terraform import google_project_service.compute_googleapis_com 937596446936/compute.googleapis.com
resource "google_project_service" "servicemanagement_googleapis_com" {
  project = "937596446936"
  service = "servicemanagement.googleapis.com"
}
# terraform import google_project_service.servicemanagement_googleapis_com 937596446936/servicemanagement.googleapis.com
resource "google_compute_url_map" "terraform_load_balancer" {
  default_service = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/backendServices/terraform-backend"
  name            = "terraform-load-balancer"
  project         = "infra-actor-333516"
}
# terraform import google_compute_url_map.terraform_load_balancer projects/infra-actor-333516/global/urlMaps/terraform-load-balancer
resource "google_project_service" "storage_component_googleapis_com" {
  project = "937596446936"
  service = "storage-component.googleapis.com"
}
# terraform import google_project_service.storage_component_googleapis_com 937596446936/storage-component.googleapis.com
resource "google_project_service" "datastore_googleapis_com" {
  project = "937596446936"
  service = "datastore.googleapis.com"
}
# terraform import google_project_service.datastore_googleapis_com 937596446936/datastore.googleapis.com
resource "google_project_service" "monitoring_googleapis_com" {
  project = "937596446936"
  service = "monitoring.googleapis.com"
}
# terraform import google_project_service.monitoring_googleapis_com 937596446936/monitoring.googleapis.com
resource "google_project_service" "clouddebugger_googleapis_com" {
  project = "937596446936"
  service = "clouddebugger.googleapis.com"
}
# terraform import google_project_service.clouddebugger_googleapis_com 937596446936/clouddebugger.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.184.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "asia-southeast2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/asia-southeast2/subnetworks/default
resource "google_project_service" "serviceusage_googleapis_com" {
  project = "937596446936"
  service = "serviceusage.googleapis.com"
}
# terraform import google_project_service.serviceusage_googleapis_com 937596446936/serviceusage.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.188.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "northamerica-northeast2"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/northamerica-northeast2/subnetworks/default
resource "google_project_service" "oslogin_googleapis_com" {
  project = "937596446936"
  service = "oslogin.googleapis.com"
}
# terraform import google_project_service.oslogin_googleapis_com 937596446936/oslogin.googleapis.com
resource "google_service_account" "937596446936_compute" {
  account_id   = "937596446936-compute"
  display_name = "Compute Engine default service account"
  project      = "infra-actor-333516"
}
# terraform import google_service_account.937596446936_compute projects/infra-actor-333516/serviceAccounts/937596446936-compute@infra-actor-333516.iam.gserviceaccount.com
resource "google_project_service" "storage_googleapis_com" {
  project = "937596446936"
  service = "storage.googleapis.com"
}
# terraform import google_project_service.storage_googleapis_com 937596446936/storage.googleapis.com
resource "google_compute_subnetwork" "default" {
  ip_cidr_range              = "10.164.0.0/20"
  name                       = "default"
  network                    = "https://www.googleapis.com/compute/v1/projects/infra-actor-333516/global/networks/default"
  private_ipv6_google_access = "DISABLE_GOOGLE_ACCESS"
  project                    = "infra-actor-333516"
  purpose                    = "PRIVATE"
  region                     = "europe-west4"
  stack_type                 = "IPV4_ONLY"
}
# terraform import google_compute_subnetwork.default projects/infra-actor-333516/regions/europe-west4/subnetworks/default
resource "google_project_service" "bigquerystorage_googleapis_com" {
  project = "937596446936"
  service = "bigquerystorage.googleapis.com"
}
# terraform import google_project_service.bigquerystorage_googleapis_com 937596446936/bigquerystorage.googleapis.com
