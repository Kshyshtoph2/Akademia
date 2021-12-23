terraform import module.load_balancer[0].target_https_proxy.terraform-load-balancer-target-proxy-2 compute.googleapis.com/projects/infra-actor-333516/global/targetHttpsProxies/terraform-load-balancer-target-proxy-2
 && terraform import module.load_balancer[0].ssl_certificate.terraform-cert compute.googleapis.com/projects/infra-actor-333516/global/sslCertificates/terraform-cert
 && terraform import module.load_balancer[0].url_map.terraform-load-balancer compute.googleapis.com/projects/infra-actor-333516/global/urlMaps/terraform-load-balancer
 && terraform import module.load_balancer[0].backend_service.terraform-backend compute.googleapis.com/projects/infra-actor-333516/global/backendServices/terraform-backend
 && terraform import module.load_balancer[0].health_check.terraform-health-check compute.googleapis.com/projects/infra-actor-333516/global/healthChecks/terraform-health-check
 && terraform import module.load_balancer[0].instance_group.instance-group-terraform compute.googleapis.com/projects/infra-actor-333516/zones/europe-central2-a/instanceGroups/instance-group-terraform
 && terraform import module.load_balancer[0].disk.terraform-instance compute.googleapis.com/projects/infra-actor-333516/zones/europe-central2-a/disks/terraform-instance
 && terraform import module.load_balancer[0].instance.terraform-instance compute.googleapis.com/projects/infra-actor-333516/zones/europe-central2-a/instances/terraform-instance
 && terraform import module.load_balancer[0].network.terraform-network compute.googleapis.com/projects/infra-actor-333516/global/networks/terraform-network
