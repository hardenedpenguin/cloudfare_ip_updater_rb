#!/usr/bin/env ruby
# Copyright (c) 2025 - 2026 Jory A. Pratt, W5GLE <geekypenguin@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

require 'net/http'
require 'json'
require 'fileutils'
require 'ipaddr'
require 'resolv'

class CloudflareIPUpdater
  CONFIG_FILE = '/etc/cloudflare-ip-updater/config'
  CLOUDFLARE_API_URL = 'https://api.cloudflare.com/client/v4'
  STORAGE_DIR = '/var/lib/cloudflare-ip-updater'
  IPV4_STORAGE_FILE = "#{STORAGE_DIR}/last_ip.txt"
  IPV6_STORAGE_FILE = "#{STORAGE_DIR}/last_ipv6.txt"

  # Services to check external IPv4
  IPV4_CHECK_SERVICES = [
    'https://api.ipify.org?format=json',
    'https://ifconfig.me/all.json',
    'https://api.myip.com'
  ]

  # Services to check external IPv6 (api6 fails if no IPv6; api64 returns v4 or v6)
  IPV6_CHECK_SERVICES = [
    'https://api6.ipify.org?format=json',
    'https://api64.ipify.org?format=json',
    'https://ipv6.icanhazip.com'
  ]

  Record = Struct.new(:domain, :record_name, :type, :zone_id, :dns_record_id, keyword_init: true) do
    def full_name
      record_name == '@' ? domain : "#{record_name}.#{domain}"
    end
  end

  DEFAULT_RETRY_ATTEMPTS = 3
  RETRY_BASE_DELAY = 2
  DEFAULT_CHECK_INTERVAL_MINUTES = 180
  DNS_VERIFY_NAMESERVERS = %w[1.1.1.1 8.8.8.8].freeze

  attr_reader :api_token, :records, :zone_cache, :dry_run

  def initialize(dry_run: false)
    @dry_run = dry_run
    load_config
    validate_config
    ensure_storage_directory
    resolve_record_ids
  end

  def load_config
    unless File.exist?(CONFIG_FILE)
      raise "Configuration file not found: #{CONFIG_FILE}"
    end

    config = {}
    record_lines = []
    File.readlines(CONFIG_FILE).each do |line|
      line = line.strip
      next if line.empty? || line.start_with?('#')

      key, value = line.split('=', 2)
      next unless key && value

      key = key.strip
      value = value.strip.gsub(/^["']|["']$/, '')  # Remove quotes

      if key.upcase == 'RECORD'
        record_lines << value
      else
        config[key] = value
      end
    end

    @api_token = config['CLOUDFLARE_API_TOKEN'] || ENV['CLOUDFLARE_API_TOKEN'] || ''
    @zone_cache = {}
    @retry_attempts = (config['RETRY_ATTEMPTS'] || ENV['RETRY_ATTEMPTS'] || DEFAULT_RETRY_ATTEMPTS).to_i
    @retry_attempts = DEFAULT_RETRY_ATTEMPTS if @retry_attempts < 1 || @retry_attempts > 10
    @check_interval_minutes = (config['CHECK_INTERVAL'] || ENV['CHECK_INTERVAL'] || DEFAULT_CHECK_INTERVAL_MINUTES).to_i
    @check_interval_minutes = DEFAULT_CHECK_INTERVAL_MINUTES if @check_interval_minutes < 1 || @check_interval_minutes > 10080
    @verify_dns = %w[1 true yes on].include?((config['VERIFY_DNS'] || ENV['VERIFY_DNS'] || '0').to_s.downcase.strip)

    # Build records list: use RECORD lines if present, else legacy single-record mode
    if record_lines.any?
      @records = record_lines.map do |rec|
        parts = rec.split(':')
        raise "Invalid RECORD format: #{rec}. Use domain:record_name:type (e.g. example.com:@:A)" if parts.size < 3
        domain = parts[0].strip
        record_name = (parts[1] || '@').strip
        type = (parts[2] || 'A').strip.upcase
        raise "Invalid DNS record type: #{type}. Use A or AAAA" unless %w[A AAAA].include?(type)
        Record.new(domain: domain, record_name: record_name, type: type)
      end.uniq
    else
      domain = config['DOMAIN'] || ENV['DOMAIN'] || ''
      record_name = config['DNS_RECORD_NAME'] || ENV['DNS_RECORD_NAME'] || '@'
      type = (config['DNS_RECORD_TYPE'] || ENV['DNS_RECORD_TYPE'] || 'A').upcase
      raise "DOMAIN must be set in #{CONFIG_FILE}" if domain.empty?
      raise "Invalid DNS record type: #{type}. Use A or AAAA" unless %w[A AAAA].include?(type)
      @records = [Record.new(domain: domain, record_name: record_name, type: type)]
    end
  end

  def validate_config
    raise "CLOUDFLARE_API_TOKEN must be set in #{CONFIG_FILE}" if @api_token.empty?
    raise "No DNS records configured" if @records.empty?
  end

  def ensure_storage_directory
    FileUtils.mkdir_p(STORAGE_DIR) unless Dir.exist?(STORAGE_DIR)
  end

  def resolve_record_ids
    @records.each do |rec|
      rec.zone_id = get_zone_id(rec.domain)
      rec.dns_record_id = get_dns_record_id(rec.zone_id, rec.full_name, rec.type)
    end
  end

  def get_zone_id(domain)
    return @zone_cache[domain] if @zone_cache[domain]

    puts "Looking up Zone ID for domain: #{domain}"
    result = make_api_request('GET', "/zones?name=#{domain}")
    if result['result'] && result['result'].any?
      zone_id = result['result'].first['id']
      puts "Found Zone ID for #{domain}: #{zone_id}"
      @zone_cache[domain] = zone_id
    else
      raise "Domain #{domain} not found in Cloudflare account"
    end
  end

  def get_dns_record_id(zone_id, full_name, type)
    puts "Looking up DNS Record ID for: #{full_name} (#{type})"
    result = make_api_request('GET', "/zones/#{zone_id}/dns_records?type=#{type}&name=#{full_name}")
    if result['result'] && result['result'].any?
      record_id = result['result'].first['id']
      puts "Found DNS Record ID: #{record_id}"
      record_id
    else
      raise "DNS record #{full_name} (#{type}) not found in Cloudflare"
    end
  end

  def get_external_ip(ipv6: false)
    retry_with_backoff do
      services = ipv6 ? IPV6_CHECK_SERVICES : IPV4_CHECK_SERVICES
      last_error = nil

      services.each do |service_url|
        begin
          uri = URI(service_url)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = (uri.scheme == 'https')
          http.open_timeout = 10
          http.read_timeout = 10
          response = http.get(uri.request_uri)

          if response.code == '200'
            body = response.body.strip
            ip = if body.start_with?('{')
              data = JSON.parse(body)
              data['ip'] || data['ip_addr'] || data['IP']
            else
              body  # Plain text response (e.g. icanhazip.com)
            end
            ip = ip.to_s.strip
            if ip && valid_ip?(ip, ipv6)
              puts "Current external #{ipv6 ? 'IPv6' : 'IPv4'}: #{ip} (from #{service_url})"
              return ip
            end
          end
        rescue => e
          last_error = e
          puts "Failed to get #{ipv6 ? 'IPv6' : 'IPv4'} from #{service_url}: #{e.message}"
          next
        end
      end

      raise last_error || "Unable to determine external #{ipv6 ? 'IPv6' : 'IPv4'} from any service"
    end
  end

  def valid_ip?(ip, ipv6)
    if ipv6
      IPAddr.new(ip).ipv6? rescue false
    else
      ip.match?(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)
    end
  end

  def get_last_known_ip(ipv6: false)
    file = ipv6 ? IPV6_STORAGE_FILE : IPV4_STORAGE_FILE
    return nil unless File.exist?(file)
    ip = File.read(file).strip
    valid_ip?(ip, ipv6) ? ip : nil
  rescue => e
    puts "Error reading last #{ipv6 ? 'IPv6' : 'IPv4'}: #{e.message}"
    nil
  end

  def save_ip(ip, ipv6: false)
    return if @dry_run
    file = ipv6 ? IPV6_STORAGE_FILE : IPV4_STORAGE_FILE
    File.write(file, ip)
  end

  def retry_with_backoff
    last_error = nil
    @retry_attempts.times do |attempt|
      begin
        return yield
      rescue => e
        last_error = e
        break if attempt == @retry_attempts - 1
        delay = RETRY_BASE_DELAY * (2**attempt)
        puts "  Retry #{attempt + 1}/#{@retry_attempts} after #{delay}s: #{e.message}"
        sleep(delay)
      end
    end
    raise last_error
  end

  def make_api_request(method, path, body = nil)
    retry_with_backoff do
      uri = URI("#{CLOUDFLARE_API_URL}#{path}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.open_timeout = 15
      http.read_timeout = 30

      request_class = case method.upcase
                      when 'GET' then Net::HTTP::Get
                      when 'PUT' then Net::HTTP::Put
                      when 'POST' then Net::HTTP::Post
                      else Net::HTTP::Get
                      end

      rate_limit_attempt = 0
      loop do
        request = request_class.new(uri)
        request['Authorization'] = "Bearer #{@api_token}"
        request['Content-Type'] = 'application/json'
        request['Accept'] = 'application/json'
        request.body = body.to_json if body

        response = http.request(request)
        result = JSON.parse(response.body) if response.body && !response.body.empty?

        if response.code.to_i >= 200 && response.code.to_i < 300
          return result
        end

        # Handle rate limit (429)
        if response.code.to_i == 429
          retry_after = response['Retry-After']&.to_i || 60
          retry_after = [retry_after, 300].min  # Cap at 5 minutes
          if rate_limit_attempt < @retry_attempts - 1
            puts "  Rate limited (429). Waiting #{retry_after}s before retry..."
            sleep(retry_after)
            rate_limit_attempt += 1
            next
          end
        end

        error_msg = result && result['errors'] ? result['errors'].map { |e| e['message'] }.join(', ') : response.body
        raise "Cloudflare API error (#{response.code}): #{error_msg}"
      end
    end
  end

  def update_dns_record(rec, new_ip)
    if @dry_run
      puts "[DRY-RUN] Would update #{rec.full_name} (#{rec.type}) to #{new_ip}"
      return true
    end

    existing_record = make_api_request('GET', "/zones/#{rec.zone_id}/dns_records/#{rec.dns_record_id}")
    record = existing_record['result']

    update_data = {
      'type' => rec.type,
      'name' => rec.full_name,
      'content' => new_ip,
      'ttl' => record['ttl'] || 3600,
      'proxied' => record['proxied'] || false
    }

    result = make_api_request('PUT', "/zones/#{rec.zone_id}/dns_records/#{rec.dns_record_id}", update_data)

    if result['success']
      puts "Successfully updated #{rec.full_name} (#{rec.type}) to #{new_ip}"
      true
    else
      raise "Failed to update DNS record: #{result['errors']}"
    end
  end

  def verify_dns_propagation(rec, expected_ip, ipv6: false)
    return unless @verify_dns && !@dry_run

    full_name = rec.full_name
    resource_class = ipv6 ? Resolv::DNS::Resource::IN::AAAA : Resolv::DNS::Resource::IN::A

    expected_normalized = IPAddr.new(expected_ip).to_s
    DNS_VERIFY_NAMESERVERS.each do |ns|
      begin
        Resolv::DNS.open(nameserver: ns) do |dns|
          answers = dns.getresources(full_name, resource_class)
          found = answers.any? { |a| IPAddr.new(a.address.to_s).to_s == expected_normalized }
          if found
            puts "  DNS propagation verified for #{full_name} (via #{ns})"
            return
          end
        end
      rescue => e
        puts "  DNS check via #{ns}: #{e.message}"
      end
    end

    puts "  DNS propagation: #{full_name} not yet resolving to #{expected_ip} (may take a few minutes)"
  end

  def check_and_update
    puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] === DRY-RUN MODE (no changes will be made) ===" if @dry_run

    needs_ipv4 = @records.any? { |r| r.type == 'A' }
    needs_ipv6 = @records.any? { |r| r.type == 'AAAA' }

    # Process IPv4 records
    if needs_ipv4
      current_ipv4 = get_external_ip(ipv6: false)
      last_ipv4 = get_last_known_ip(ipv6: false)
      a_records = @records.select { |r| r.type == 'A' }

      if last_ipv4.nil?
        puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] No previous IPv4 found. Saving: #{current_ipv4}"
        puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] [DRY-RUN] Would save IPv4" if @dry_run
        save_ip(current_ipv4, ipv6: false)
      elsif current_ipv4 != last_ipv4
        puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] IPv4 changed from #{last_ipv4} to #{current_ipv4}"
        puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] Updating Cloudflare DNS (A records)..."
        a_records.each do |rec|
          update_dns_record(rec, current_ipv4)
          verify_dns_propagation(rec, current_ipv4, ipv6: false)
        end
        save_ip(current_ipv4, ipv6: false)
        puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] IPv4 update complete!"
      else
        puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] IPv4 unchanged (#{current_ipv4}) - no update needed"
      end
    end

    # Process IPv6 records (skip IP check if no AAAA records)
    if needs_ipv6
      begin
        current_ipv6 = get_external_ip(ipv6: true)
        last_ipv6 = get_last_known_ip(ipv6: true)
        aaaa_records = @records.select { |r| r.type == 'AAAA' }

        if last_ipv6.nil?
          puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] No previous IPv6 found. Saving: #{current_ipv6}"
          puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] [DRY-RUN] Would save IPv6" if @dry_run
          save_ip(current_ipv6, ipv6: true)
        elsif current_ipv6 != last_ipv6
          puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] IPv6 changed from #{last_ipv6} to #{current_ipv6}"
          puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] Updating Cloudflare DNS (AAAA records)..."
          aaaa_records.each do |rec|
            update_dns_record(rec, current_ipv6)
            verify_dns_propagation(rec, current_ipv6, ipv6: true)
          end
          save_ip(current_ipv6, ipv6: true)
          puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] IPv6 update complete!"
        else
          puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] IPv6 unchanged (#{current_ipv6}) - no update needed"
        end
      rescue => e
        puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] IPv6 check/update failed: #{e.message}"
        puts "  (If you have no IPv6 connectivity, remove AAAA records from config or ignore this message)"
      end
    end
  end

  def self.setup_timer_from_config
    config = {}
    if File.exist?(CONFIG_FILE)
      File.readlines(CONFIG_FILE).each do |line|
        line = line.strip
        next if line.empty? || line.start_with?('#')
        key, value = line.split('=', 2)
        next unless key && value
        config[key.strip] = value.strip.gsub(/^["']|["']$/, '')
      end
    end
    minutes = (config['CHECK_INTERVAL'] || ENV['CHECK_INTERVAL'] || DEFAULT_CHECK_INTERVAL_MINUTES).to_i
    minutes = DEFAULT_CHECK_INTERVAL_MINUTES if minutes < 1 || minutes > 10080
    dropin_dir = '/etc/systemd/system/cloudflare-ip-updater.timer.d'
    FileUtils.mkdir_p(dropin_dir) unless Dir.exist?(dropin_dir)
    File.write("#{dropin_dir}/override.conf", "[Timer]\nOnUnitActiveSec=#{minutes}min\n")
    system('systemctl', 'daemon-reload')
    system('systemctl', 'restart', 'cloudflare-ip-updater.timer') || true
    puts "Timer interval set to #{minutes} minutes"
  end
end

# Main execution
if __FILE__ == $0
  begin
    if ARGV.include?('--help') || ARGV.include?('-h')
      puts <<~HELP
        Cloudflare IP Updater

        This script checks your external IP address (IPv4 and/or IPv6) and updates your
        Cloudflare DNS records automatically when they change. Supports multiple records
        and domains. Designed to run via systemd timer.

        Configuration:
          Configuration is read from /etc/cloudflare-ip-updater/config

          Required:
            CLOUDFLARE_API_TOKEN       - Your Cloudflare API token

          Multi-record mode (RECORD=domain:record_name:type, one per line):
            RECORD=example.com:@:A           - Root domain A record (IPv4)
            RECORD=example.com:@:AAAA        - Root domain AAAA record (IPv6)
            RECORD=example.com:home:A        - Subdomain home.example.com (IPv4)
            RECORD=other.com:vpn:AAAA        - Different domain (IPv6)
            ...add more RECORD lines as needed

          Legacy single-record mode (if no RECORD lines):
            DOMAIN                     - Your domain name (e.g., example.com)
            DNS_RECORD_NAME            - @ for root, or subdomain (default: @)
            DNS_RECORD_TYPE            - A (IPv4) or AAAA (IPv6) (default: A)

          Optional:
            CHECK_INTERVAL              - Check interval in minutes (default: 180)
            RETRY_ATTEMPTS             - API/IP check retries (default: 3)
            VERIFY_DNS                 - Verify propagation after update (1/0, default: 0)

        Usage:
          # Run once (typically called by systemd timer)
          /usr/sbin/cloudflare-ip-updater

          # Dry-run (show what would be updated, make no changes)
          /usr/sbin/cloudflare-ip-updater --dry-run

          # Apply CHECK_INTERVAL from config to systemd timer
          /usr/sbin/cloudflare-ip-updater --setup-timer

          # View help
          /usr/sbin/cloudflare-ip-updater --help

        Service Management:
          # Enable and start the timer
          sudo systemctl enable cloudflare-ip-updater.service
          sudo systemctl enable --now cloudflare-ip-updater.timer

          # Check timer status
          sudo systemctl status cloudflare-ip-updater.timer

          # Check service logs
          sudo journalctl -u cloudflare-ip-updater.service

          # Manually trigger a check
          sudo systemctl start cloudflare-ip-updater.service

        To get Cloudflare API token:
          1. Go to https://dash.cloudflare.com/profile/api-tokens
          2. Click "Create Token"
          3. Use "Edit zone DNS" template or create custom token with Zone:Zone:Read and Zone:DNS:Edit permissions
          4. Add token to /etc/cloudflare-ip-updater/config
      HELP
      exit 0
    end

    if ARGV.include?('--setup-timer')
      CloudflareIPUpdater.setup_timer_from_config
      exit 0
    end

    dry_run = ARGV.include?('--dry-run')
    updater = CloudflareIPUpdater.new(dry_run: dry_run)
    updater.check_and_update
  rescue => e
    puts "Error: #{e.message}"
    puts e.backtrace if ENV['DEBUG']
    exit 1
  end
end
