{{/*
certhub-server.listenPort returns the TCP port the server listens on. The
server config (config.yaml, key http.bind_addr) is the single source of truth.
The server uses ":8080" when http.bind_addr is not set. The container port,
the probes and the Service targetPort follow this value. service.port changes
only the port that the Service exposes.
*/}}
{{- define "certhub-server.listenPort" -}}
{{- $config := fromYaml .Values.config.yaml -}}
{{- if hasKey $config "Error" -}}
{{- fail (printf "config.yaml is not valid YAML: %s" (get $config "Error")) -}}
{{- end -}}
{{- $http := get $config "http" | default dict -}}
{{- if not (kindIs "map" $http) -}}
{{- fail "config.yaml: http must be a mapping" -}}
{{- end -}}
{{- $bindAddr := get $http "bind_addr" | default ":8080" | toString -}}
{{- if not (regexMatch "^.*:[0-9]+$" $bindAddr) -}}
{{- fail (printf "config.yaml http.bind_addr %q must end with a numeric port, for example \":8080\"" $bindAddr) -}}
{{- end -}}
{{- $port := regexReplaceAll "^.*:([0-9]+)$" $bindAddr "${1}" | atoi -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail (printf "config.yaml http.bind_addr %q must use a port from 1 to 65535" $bindAddr) -}}
{{- end -}}
{{- $port -}}
{{- end -}}
