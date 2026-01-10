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

class GoDaddyIPUpdater
  CONFIG_FILE = '/etc/godaddy-ip-updater/config'
  GODADDY_API_URL = 'https://api.godaddy.com/v1'
  IP_STORAGE_FILE = '/var/lib/godaddy-ip-updater/last_ip.txt'

  # Services to check external IP
  IP_CHECK_SERVICES = [
    'https://api.ipify.org?format=json',
    'https://ifconfig.me/all.json',
    'https://api.myip.com'
  ]

  attr_reader :godaddy_api_key, :godaddy_api_secret, :domain, :dns_record_name, :dns_record_type

  def initialize
    load_config
    validate_config
    ensure_ip_storage_directory
  end

  def load_config
    unless File.exist?(CONFIG_FILE)
      raise "Configuration file not found: #{CONFIG_FILE}"
    end

    config = {}
    File.readlines(CONFIG_FILE).each do |line|
      line = line.strip
      next if line.empty? || line.start_with?('#')
      
      key, value = line.split('=', 2)
      next unless key && value
      
      key = key.strip
      value = value.strip.gsub(/^["']|["']$/, '')  # Remove quotes
      config[key] = value
    end

    @godaddy_api_key = config['GODADDY_API_KEY'] || ENV['GODADDY_API_KEY'] || ''
    @godaddy_api_secret = config['GODADDY_API_SECRET'] || ENV['GODADDY_API_SECRET'] || ''
    @domain = config['GODADDY_DOMAIN'] || ENV['GODADDY_DOMAIN'] || ''
    @dns_record_name = config['DNS_RECORD_NAME'] || ENV['DNS_RECORD_NAME'] || '@'
    @dns_record_type = config['DNS_RECORD_TYPE'] || ENV['DNS_RECORD_TYPE'] || 'A'
  end

  def validate_config
    if @godaddy_api_key.empty? || @godaddy_api_secret.empty?
      raise "GODADDY_API_KEY and GODADDY_API_SECRET must be set in #{CONFIG_FILE}"
    end
    if @domain.empty?
      raise "GODADDY_DOMAIN must be set in #{CONFIG_FILE}"
    end
  end

  def ensure_ip_storage_directory
    dir = File.dirname(IP_STORAGE_FILE)
    FileUtils.mkdir_p(dir) unless Dir.exist?(dir)
  end

  def get_external_ip
    IP_CHECK_SERVICES.each do |service_url|
      begin
        uri = URI(service_url)
        response = Net::HTTP.get_response(uri)
        
        if response.code == '200'
          data = JSON.parse(response.body)
          # Different services return IP in different formats
          ip = data['ip'] || data['ip_addr'] || data['IP']
          if ip && ip.match?(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)
            puts "Current external IP: #{ip} (from #{service_url})"
            return ip
          end
        end
      rescue => e
        puts "Failed to get IP from #{service_url}: #{e.message}"
        next
      end
    end
    
    raise "Unable to determine external IP from any service"
  end

  def get_last_known_ip
    return nil unless File.exist?(IP_STORAGE_FILE)
    ip = File.read(IP_STORAGE_FILE).strip
    ip.match?(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) ? ip : nil
  rescue => e
    puts "Error reading last IP: #{e.message}"
    nil
  end

  def save_ip(ip)
    File.write(IP_STORAGE_FILE, ip)
  end

  def get_current_dns_record
    uri = URI("#{GODADDY_API_URL}/domains/#{@domain}/records/#{@dns_record_type}/#{@dns_record_name}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    request = Net::HTTP::Get.new(uri)
    request['Authorization'] = "sso-key #{@godaddy_api_key}:#{@godaddy_api_secret}"
    request['Accept'] = 'application/json'

    response = http.request(request)
    
    if response.code == '200'
      records = JSON.parse(response.body)
      # Find the record (there might be multiple)
      record = records.find { |r| r['name'] == @dns_record_name && r['type'] == @dns_record_type }
      record ? record['data'] : nil
    elsif response.code == '404'
      nil  # Record doesn't exist yet
    else
      raise "GoDaddy API error (#{response.code}): #{response.body}"
    end
  end

  def update_dns_record(new_ip)
    uri = URI("#{GODADDY_API_URL}/domains/#{@domain}/records/#{@dns_record_type}/#{@dns_record_name}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    # Get existing records to preserve TTL and other settings
    current_record = get_current_dns_record
    ttl = current_record ? 600 : 3600  # Default TTL

    # Prepare the record data
    record_data = {
      'data' => new_ip,
      'ttl' => ttl
    }

    request = Net::HTTP::Put.new(uri)
    request['Authorization'] = "sso-key #{@godaddy_api_key}:#{@godaddy_api_secret}"
    request['Content-Type'] = 'application/json'
    request['Accept'] = 'application/json'
    request.body = [record_data].to_json

    response = http.request(request)
    
    if response.code == '200'
      puts "Successfully updated DNS record #{@dns_record_name}.#{@domain} to #{new_ip}"
      true
    else
      raise "Failed to update DNS record (#{response.code}): #{response.body}"
    end
  end

  def check_and_update
    current_ip = get_external_ip
    last_ip = get_last_known_ip

    if last_ip.nil?
      puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] No previous IP found. Saving current IP: #{current_ip}"
      save_ip(current_ip)
    elsif current_ip != last_ip
      puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] IP changed from #{last_ip} to #{current_ip}"
      puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] Updating GoDaddy DNS..."
      update_dns_record(current_ip)
      save_ip(current_ip)
      puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] Update complete!"
    else
      puts "[#{Time.now.strftime('%Y-%m-%d %H:%M:%S')}] IP unchanged (#{current_ip}) - no update needed"
    end
  end
end

# Main execution
if __FILE__ == $0
  begin
    updater = GoDaddyIPUpdater.new
    
    if ARGV.include?('--help') || ARGV.include?('-h')
      puts <<~HELP
        GoDaddy IP Updater
        
        This script checks your external IP address and updates your GoDaddy DNS
        records automatically when it changes. It is designed to run via systemd timer.
        
        Configuration:
          Configuration is read from /etc/godaddy-ip-updater/config
          
          Required settings:
            GODADDY_API_KEY          - Your GoDaddy API key
            GODADDY_API_SECRET       - Your GoDaddy API secret
            GODADDY_DOMAIN           - Your domain name (e.g., example.com)
          
          Optional settings:
            DNS_RECORD_NAME          - DNS record name (@ for root, or subdomain) (default: @)
            DNS_RECORD_TYPE          - DNS record type (default: A)
        
        Usage:
          # Run once (typically called by systemd timer)
          /usr/sbin/godaddy-ip-updater
          
          # View help
          /usr/sbin/godaddy-ip-updater --help
          
        Service Management:
          # Enable and start the timer
          sudo systemctl enable --now godaddy-ip-updater.timer
          
          # Check timer status
          sudo systemctl status godaddy-ip-updater.timer
          
          # Check service logs
          sudo journalctl -u godaddy-ip-updater.service
          
          # Manually trigger a check
          sudo systemctl start godaddy-ip-updater.service
      
        To get GoDaddy API credentials:
          1. Go to https://developer.godaddy.com/
          2. Sign in with your GoDaddy account
          3. Create a new API key with Production access
          4. Add credentials to /etc/godaddy-ip-updater/config
      HELP
      exit 0
    else
      updater.check_and_update
    end
  rescue => e
    puts "Error: #{e.message}"
    puts e.backtrace if ENV['DEBUG']
    exit 1
  end
end