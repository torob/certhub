local health = {
  status = "Progressing",
  message = "Waiting for the operator to report status"
}

if obj.status == nil then
  return health
end

local generation = nil
if obj.metadata ~= nil then
  generation = obj.metadata.generation
end

if generation == nil or obj.status.observedGeneration == nil or
    obj.status.observedGeneration ~= generation then
  health.message = "Waiting for the operator to observe the current generation"
  return health
end

if obj.status.phase == "Failed" then
  health.status = "Degraded"
  health.message = obj.status.message or "Certificate reconciliation failed"
  return health
end

local ready = false
local secretSynced = false
if obj.status.conditions ~= nil then
  for _, condition in ipairs(obj.status.conditions) do
    if condition.type == "Ready" and condition.status == "True" then
      ready = true
    elseif condition.type == "SecretSynced" and condition.status == "True" then
      secretSynced = true
    end
  end
end

if ready and secretSynced then
  health.status = "Healthy"
  health.message = "Certificate is ready and its TLS Secret is synchronized"
  return health
end

if obj.status.message ~= nil and obj.status.message ~= "" then
  health.message = obj.status.message
elseif obj.status.phase ~= nil and obj.status.phase ~= "" then
  health.message = "Certificate phase: " .. obj.status.phase
else
  health.message = "Waiting for certificate readiness and Secret synchronization"
end

return health
