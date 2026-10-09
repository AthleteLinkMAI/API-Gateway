#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"
require "pathname"

ROOT = Pathname.new(__dir__).parent
CONTRACTS = ROOT.join("docs/contracts")
OUTPUT = CONTRACTS.join("gateway-openapi.yaml")
HTTP_METHODS = %w[get post put patch delete head options trace].freeze
SERVICE_FILES = {
  "Core" => "core-service-openapi.yaml",
  "Auth" => "auth-service-openapi.yaml",
  "Game" => "game-service-openapi.yaml"
}.freeze

def rewrite_refs(value, service)
  case value
  when Hash
    value.each do |key, child|
      if key == "$ref" && child.start_with?("#/components/schemas/")
        value[key] = child.sub("#/components/schemas/", "#/components/schemas/#{service}_")
      else
        rewrite_refs(child, service)
      end
    end
  when Array
    value.each { |child| rewrite_refs(child, service) }
  end
end

def route_policies
  source = ROOT.join("internal/httpapi/routes.go").read
  pattern = /\{http\.Method(\w+),\s*"([^"]+)",\s*(authUpstream|gameUpstream|coreUpstream),\s*(\w+)\}/
  policies = {}
  source.scan(pattern).each do |method, path, upstream, access|
    key = [method.downcase, path]
    raise "duplicate Gateway route: #{key.join(' ')}" if policies.key?(key)

    unless %w[publicAccess authenticatedAccess ownUserAccess currentUserAccess].include?(access)
      raise "unknown access policy for #{key.join(' ')}: #{access}"
    end
    policies[key] = { "upstream" => upstream, "access" => access }
  end
  raise "no routes found in internal/httpapi/routes.go" if policies.empty?

  policies
end

def gateway_error_responses(operation, access)
  responses = operation.fetch("responses")
  if access != "publicAccess"
    responses["401"] ||= { "description" => "Gateway отклонил запрос из-за отсутствующего или недействительного токена доступа." }
    responses["503"] ||= { "description" => "Gateway не смог завершить проверку списка отозванных токенов доступа." }
  end
  if access == "ownUserAccess"
    responses["403"] ||= { "description" => "Gateway отклонил userId, не совпадающий с субъектом токена доступа." }
  end
  responses["502"] ||= { "description" => "Gateway не смог соединиться с целевым сервисом." }
  responses["504"] ||= { "description" => "Gateway не дождался ответа целевого сервиса до истечения тайм-аута." }

  responses.each_value do |response|
    response["headers"] ||= {}
    response["headers"]["X-Request-Id"] = {
      "description" => "UUID, сгенерированный Gateway для этого запроса.",
      "schema" => { "type" => "string", "format" => "uuid" }
    }
  end
end

def health_operation(name, ready: false)
  responses = {
    "200" => {
      "description" => ready ? "Gateway и настроенные зависимости готовы." : "Процесс Gateway работает.",
      "content" => { "text/plain" => { "schema" => { "type" => "string", "example" => "ok\n" } } }
    }
  }
  if ready
    responses["503"] = {
      "description" => "Gateway или настроенная зависимость не готовы.",
      "content" => { "text/plain" => { "schema" => { "type" => "string", "example" => "not ready\n" } } }
    }
  end
  responses.each_value do |response|
    response["headers"] = {
      "X-Request-Id" => {
        "description" => "UUID, сгенерированный Gateway для этого запроса.",
        "schema" => { "type" => "string", "format" => "uuid" }
      }
    }
  end
  { "operationId" => name, "tags" => ["Gateway"], "security" => [], "responses" => responses }
end

policies = route_policies
seen_routes = {}
operation_ids = {}
output = {
  "openapi" => "3.1.0",
  "info" => {
    "title" => "AthleteLink — шлюз API",
    "version" => "draft",
    "description" => "Черновой публичный HTTP-контракт, собранный из снимков OpenAPI Core, Auth и Game в репозитории и таблицы маршрутов Gateway. Gateway пересылает тела запросов и ответов целевых сервисов без преобразования. Core, Auth и Game предоставляют только пары метода и пути из таблицы маршрутов Gateway. Снимки Core и Auth сейчас расходятся с согласованными путями /api/v1; соответствие работающим сервисам не проверено. Для собственных ошибок Gateway нет обязательной схемы тела ответа."
  },
  "servers" => [{ "url" => "/", "description" => "Корень Gateway; источник развёртывания настраивается отдельно." }],
  "paths" => {},
  "components" => {
    "securitySchemes" => {
      "BearerAuth" => { "type" => "http", "scheme" => "bearer", "bearerFormat" => "JWT" }
    },
    "schemas" => {}
  }
}

SERVICE_FILES.each do |service, filename|
  source = YAML.load_file(CONTRACTS.join(filename))
  rewrite_refs(source, service)
  source.fetch("components").fetch("schemas").each do |name, schema|
    output["components"]["schemas"]["#{service}_#{name}"] = schema
  end

  source.fetch("paths").each do |source_path, path_item|
    next if service == "Auth" && source_path == "/health"

    public_path = "/api/v1#{source_path}"
    current_user = service == "Auth" && source_path.end_with?("/{userId}") &&
      path_item.keys.any? { |method| policies[[method, public_path.delete_suffix("/{userId}")]]&.fetch("access") == "currentUserAccess" }
    public_path = public_path.delete_suffix("/{userId}") if current_user
    raise "duplicate public path: #{public_path}" if output["paths"].key?(public_path)

    output["paths"][public_path] = {}
    path_item.each do |method, operation|
      next unless HTTP_METHODS.include?(method)

      key = [method, public_path]
      policy = policies.fetch(key) { raise "snapshot route absent from Gateway: #{key.join(' ')}" }
      expected = "#{service.downcase}Upstream"
      raise "wrong upstream for #{key.join(' ')}" unless policy["upstream"] == expected

      access = policy["access"]
      if current_user && access != "currentUserAccess"
        raise "invalid current-user route policy: #{key.join(' ')}"
      end
      seen_routes[key] = true
      if service == "Core"
        # Core expects this trusted header from the Gateway, never from its public caller.
        operation["parameters"]&.reject! do |parameter|
          parameter["in"] == "header" && parameter["name"].casecmp?("X-User-Id")
        end
      end

      operation_id = operation.fetch("operationId")
      raise "duplicate operationId: #{operation_id}" if operation_ids.key?(operation_id)

      operation_ids[operation_id] = true
      operation["security"] = access == "publicAccess" ? [] : [{ "BearerAuth" => [] }]
      if current_user
        operation["parameters"]&.reject! { |parameter| parameter["in"] == "path" && parameter["name"] == "userId" }
        operation["description"] = [operation["description"], "Gateway пересылает этот вызов на #{public_path}/{sub}, используя только субъект проверенного токена доступа. Клиентские заголовки идентичности и параметры запроса не могут выбрать пользователя."].compact.join("\n\n")
      end
      if access == "ownUserAccess"
        operation["description"] = [operation["description"], "Gateway требует совпадения userId с субъектом токена доступа."].compact.join("\n\n")
      end
      gateway_error_responses(operation, access)
      output["paths"][public_path][method] = operation
    end
  end
end

{
  "/api/v1/players" => "getCurrentPlayerSummary",
  "/api/v1/players/" => "getCurrentPlayerSummaryTrailingSlash"
}.each do |path, operation_id|
  key = ["get", path]
  policy = policies.fetch(key)
  raise "invalid current-player route policy: #{path}" unless policy == { "upstream" => "gameUpstream", "access" => "authenticatedAccess" }
  raise "duplicate public path: #{path}" if output["paths"].key?(path)
  raise "duplicate operationId: #{operation_id}" if operation_ids.key?(operation_id)

  operation = Marshal.load(Marshal.dump(output.fetch("paths").fetch("/api/v1/players/{userId}").fetch("get")))
  operation["operationId"] = operation_id
  operation["summary"] = "Получить сводку текущего игрока"
  operation["description"] = "Gateway пересылает этот вызов на /api/v1/players/{sub}, используя субъект проверенного токена доступа. /api/v1/players и /api/v1/players/ работают без перенаправления."
  operation["parameters"]&.reject! { |parameter| parameter["in"] == "path" && parameter["name"] == "userId" }
  output["paths"][path] = { "get" => operation }
  operation_ids[operation_id] = true
  seen_routes[key] = true
end

missing = policies.keys - seen_routes.keys
raise "Gateway routes absent from snapshots: #{missing.inspect}" unless missing.empty?

output["paths"]["/healthz"] = { "get" => health_operation("gatewayHealth") }
output["paths"]["/readyz"] = { "get" => health_operation("gatewayReadiness", ready: true) }

check_refs = lambda do |value|
  case value
  when Hash
    value.each do |key, child|
      if key == "$ref" && child.start_with?("#/components/schemas/")
        name = child.delete_prefix("#/components/schemas/")
        raise "unresolved schema reference: #{child}" unless output["components"]["schemas"].key?(name)
      else
        check_refs.call(child)
      end
    end
  when Array
    value.each { |child| check_refs.call(child) }
  end
end
check_refs.call(output)

document = "# Сгенерировано scripts/build_gateway_openapi.rb из снимков сервисов в репозитории.\n"
document += "# Черновик: совместимость /api/v1 Core и Auth с работающими сервисами не проверена.\n"
document += YAML.dump(output)

if ARGV == ["--check"]
  abort "#{OUTPUT} is stale; run ruby scripts/build_gateway_openapi.rb" unless OUTPUT.file? && OUTPUT.read == document
  puts "#{OUTPUT} is current"
elsif ARGV.empty?
  OUTPUT.write(document)
  puts "wrote #{OUTPUT}"
else
  abort "usage: ruby scripts/build_gateway_openapi.rb [--check]"
end
