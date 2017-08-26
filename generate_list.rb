#!/usr/bin/env ruby

require 'resolv'

hosts = File.open('hosts.txt', 'r').read.split("\n")
blocks = {}
File.open('hosts.txt', 'r').read.split("\n").each do |line|
  next if line.empty? or line[0] == '#'
  host, ports = line.split(':')
  blocks[host] ||= {}
  blocks[host]['ports'] ||= []
  blocks[host]['ports'] << (ports || '*')
	blocks[host]['ips'] ||= []
  blocks[host]['ips'] += Resolv::DNS.new.getresources(host, Resolv::DNS::Resource::IN::A).map{|a| a.address.to_s}
end

# TODO: handle cluster designations, eg 217.12.16.0/20

File.open('blocklist.txt', 'w') do |f|
  blocks.each do |host, h|
    f << "# #{host}#{" - ports #{h['ports'].join(', ')}" if h['ports'] != ['*']}\n"
    h['ips'].each do |ip|
      h['ports'].each do |port|
        f << "ExitPolicy reject #{ip}:#{port}\n"
      end
    end
  end
end
