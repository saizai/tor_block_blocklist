#!/usr/bin/env ruby

require 'json'
require 'neatjson'

require 'passivedns/client' # gem install passivedns-client
require "./passivedns_resolv.rb"

@providers = ['dnsdb', 'resolv']    # default providers: bfk, tcpiputils, certee, dnsdb, virustotal, passivedns.cn, mnemonic
@dns = PassiveDNS::Client.new(@providers)
@rrsets = JSON.parse(File.read('rrsets.txt')) rescue {}
@rrsets_now = {} # TODO: smarter caching to deal with rate limiting

def recursive_get host
  puts "querying #{host}"
  rrset = if @rrsets_now[host]
    puts "... cached"
    @rrsets[host]
  else
    begin
      r = @dns.query(host)
      @rrsets[host] = r # separated to allow error first
      @rrsets_now[host] = true
      if !r.blank?
        File.open('rrsets.tmp', 'w') do |f|
          f << JSON.neat_generate(@rrsets, aligned: true)
        end
        File.rename 'rrsets.tmp', 'rrsets.txt'
      end
      r
    rescue PassiveDNS::Provider::DNSDB::Exception # rate limit
      @dns = PassiveDNS::Client.new(@providers - ['dnsdb'])
      retry
    end
    puts @rrsets[host]
    @rrsets[host]
  end
  ret = {}

  ips = rrset.select{|r| %w(A AAAA).include? r['rrtype']}.map{|r| r['answer']}
  recurse_on = rrset.select{|r| %w(CNAME PTR).include? r['rrtype']}.map{|r| r['answer']}

  recursive_results = recurse_on.map{|recursion| recursive_get recursion}
  ret[:ips] = (recursive_results.map{|r| r[:ips]} + ips).flatten.uniq.sort
  ret[:recurse_on] = (recursive_results.map{|r| r[:recurse_on]} + recurse_on).flatten.uniq.sort
  ret
end

# hosts = File.open('hosts.txt', 'r').read.split("\n")

blocks = {}
File.open('hosts.txt', 'r').read.split("\n").each do |line|
  puts "line: #{line}"
  next if line.empty? or line[0] == '#'
  host, ports = line.split(':')
  blocks[host] ||= {}
  blocks[host]['ports'] ||= []
  blocks[host]['ports'] << (ports || '*')
	blocks[host]['ips'] ||= []
  blocks[host]['ips'] += recursive_get(host)[:ips]
  blocks[host]['ips'] = blocks[host]['ips'].uniq
end

# TODO: handle cluster designations, eg 217.12.16.0/20

File.open('blocklist.txt', 'w') do |f|
  blocks.each do |host, h|
    f << "# #{host}#{" - ports #{h['ports'].join(', ')}" if h['ports'] != ['*']}\n"
    h['ips'].each do |ip|
      h['ports'].each do |port|
        f << "ExitPolicy reject#{ '6' if ip.include?(':') } #{ip}:#{port}\n" unless ip.include?(':') # FIXME: Malformed policy 'reject6 2400:CB00:2048:1::681C:1493:*'. Discarding entire policy list.
      end
    end
  end
end
