#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "cgi"
require "json"
require "pathname"
require "yaml"

ROOT = Pathname.new(__dir__).parent
UI = ROOT.join("docs/swagger-ui")
SPEC = ROOT.join("docs/contracts/gateway-openapi.yaml")
OUTPUT = ROOT.join("docs/swagger-standalone.html")

def asset(name)
  UI.join(name).read
end

def inline_asset(name, closing_tag)
  contents = asset(name)
  raise "#{name} contains </#{closing_tag}> and cannot be embedded safely" if contents.match?(%r{</#{closing_tag}}i)

  contents
end

def inline_schema_refs(value, schemas, stack = [])
  case value
  when Hash
    if value.key?("$ref")
      siblings = value.keys - ["$ref"]
      raise "schema reference has unsupported sibling fields: #{siblings.inspect}" unless (siblings - ["description"]).empty?

      reference = value.fetch("$ref")
      prefix = "#/components/schemas/"
      raise "unsupported external reference: #{reference}" unless reference.start_with?(prefix)

      name = reference.delete_prefix(prefix)
      raise "missing schema: #{name}" unless schemas.key?(name)
      raise "cyclic schema reference: #{(stack + [name]).join(' -> ')}" if stack.include?(name)

      resolved = inline_schema_refs(schemas.fetch(name), schemas, stack + [name])
      return resolved unless value.key?("description")

      raise "described schema reference does not resolve to an object: #{reference}" unless resolved.is_a?(Hash)
      return resolved.merge("description" => value.fetch("description"))
    end

    value.transform_values { |child| inline_schema_refs(child, schemas, stack) }
  when Array
    value.map { |child| inline_schema_refs(child, schemas, stack) }
  else
    value
  end
end

source_spec = YAML.load_file(SPEC)
schemas = source_spec.fetch("components").fetch("schemas")
spec_json = JSON.generate(inline_schema_refs(source_spec, schemas))
spec_json = spec_json.gsub("<", "\\u003c").gsub(">", "\\u003e").gsub("&", "\\u0026")
favicon = Base64.strict_encode64(UI.join("favicon-32x32.png").binread)

license_names = %w[LICENSE NOTICE swagger-ui-bundle.js.LICENSE.txt swagger-ui-standalone-preset.js.LICENSE.txt]
licenses = license_names.map do |name|
  "<h3>#{CGI.escapeHTML(name)}</h3><pre>#{CGI.escapeHTML(asset(name))}</pre>"
end.join("\n")

html = <<~HTML
  <!doctype html>
  <html lang="ru">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AthleteLink Gateway — Swagger UI</title>
    <link rel="icon" href="data:image/png;base64,#{favicon}">
    <style>#{inline_asset('index.css', 'style')}</style>
    <style>#{inline_asset('swagger-ui.css', 'style')}</style>
    <style>
      .gateway-notice { padding: 12px 20px; background: #fff4d6; color: #302b20; font: 14px/1.45 sans-serif; }
      .gateway-notice strong { display: block; margin-bottom: 4px; }
      .gateway-license { margin: 32px 20px; font: 13px/1.4 sans-serif; }
      .gateway-license pre { white-space: pre-wrap; overflow-wrap: anywhere; }
    </style>
  </head>
  <body>
    <div class="gateway-notice">
      <strong>Черновая документация AthleteLink Gateway</strong>
      Контракты Core, Auth и Game пока не сверены с работающими сервисами.
      <span id="gateway-connection">Просмотр доступен без подключения к API. Для Try it out добавьте к адресу страницы параметр ?gateway=https://адрес-gateway.</span>
    </div>
    <div id="swagger-ui"></div>
    <details class="gateway-license">
      <summary>Лицензии встроенного Swagger UI 5.33.1</summary>
      #{licenses}
    </details>
    <script>#{inline_asset('swagger-ui-bundle.js', 'script')}</script>
    <script>#{inline_asset('swagger-ui-standalone-preset.js', 'script')}</script>
    <script type="application/json" id="gateway-openapi">#{spec_json}</script>
    <script>
      window.addEventListener("load", function () {
        const spec = JSON.parse(document.getElementById("gateway-openapi").textContent);
        const gatewayParam = new URLSearchParams(window.location.search).get("gateway");
        let gateway = null;
        if (gatewayParam) {
          try {
            const parsed = new URL(gatewayParam);
            if (parsed.protocol === "http:" || parsed.protocol === "https:") {
              gateway = parsed.origin;
            }
          } catch (_) { /* Keep documentation available when the URL is invalid. */ }
        }

        const config = {
          spec: spec,
          dom_id: "#swagger-ui",
          deepLinking: true,
          validatorUrl: "none",
          presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
          plugins: [SwaggerUIBundle.plugins.DownloadUrl],
          layout: "StandaloneLayout"
        };
        if (gateway) {
          spec.servers = [{ url: gateway }];
          document.getElementById("gateway-connection").textContent = "Try it out отправляет запросы на " + gateway + ".";
        } else {
          config.supportedSubmitMethods = [];
        }
        window.ui = SwaggerUIBundle(config);
      });
    </script>
  </body>
  </html>
HTML

if ARGV == ["--check"]
  abort "#{OUTPUT} is stale; run ruby scripts/build_standalone_swagger.rb" unless OUTPUT.file? && OUTPUT.read == html
  puts "#{OUTPUT} is current"
elsif ARGV.empty?
  OUTPUT.write(html)
  puts "wrote #{OUTPUT} (#{html.bytesize} bytes)"
else
  abort "usage: ruby scripts/build_standalone_swagger.rb [--check]"
end
