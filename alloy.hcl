logging {
  level  = "info"
  format = "logfmt"
}

local.file_match "django_logs" {
  path_targets = [{"__path__" = "/app/logs/django.log"}]
  sync_period  = "5s"
}

loki.source.file "django_source" {
  targets    = local.file_match.django_logs.targets
  forward_to = [loki.write.local.receiver]
}

loki.write "local" {
  endpoint {
    url = "http://loki:3100/loki/api/v1/push"
  }
}
