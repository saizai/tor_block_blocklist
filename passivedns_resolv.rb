require 'resolv'

module PassiveDNS
  module Provider
    class PassiveResolv < PassiveDB
      def self.name
        "resolv"
      end

      def self.config_section_name
        'resolv'
      end

      def self.option_letter
        'l'
      end

      def initialize(options={})
        @resolv = Resolv::DNS.new
      end

      def lookup(label, limit=nil)
        prev = JSON.parse(File.read('rrsets.txt'))[label].select{|r| r['source'] =~ /^resolv$/i} rescue nil
        results = []
        # also does:
        # :HINFO > :cpu, :os
        # :LOC > :version, :ssize, :hprecision, :vprecision, :latitude, :longitude, :altitude
        # :MINFO > :rmailbx, :emailbx
        # :SOA > :mname, :rname, :serial, :refresh, :retry, :expire, :minimum
        # :SRV > :priority, :weight, :port, :target
        # :WKS > address, protocol, bitmap
        [:A, :AAAA, :CNAME, :MX, :NS, :PTR, :TXT].each do |rrtype|
          begin
            Timeout::timeout(20) do
              t1 = Time.now
              rr = @resolv.getresources(label, Resolv::DNS::Resource::IN.const_get(rrtype))
              t2 = Time.now
              rr.each do |a|
                a_prev_time = prev.select{|r| r['query'] == label && r['rrtype'] == rrtype}.first['firstseen'] rescue Time.now

                answer = case rrtype
                when :A, :AAAA
                  a.address
                when :NS, :CNAME, :PTR
                  a.name
                when :TXT
                  a.strings
                when :MX
                  a.exchange # .preference is ignored
                end

                # PDNSResult.new(:source, :response_time, :query, :answer, :rrtype, :ttl, :firstseen, :lastseen, :count, :security)
                # e.g.: DNSDB 1.608879 e6550.g.akamaiedge.net.0.1.cn.akamaiedge.net 2.17.55.136 A 0 2016-07-21 02:54:46 +0200 2016-09-01 15:52:01 +0200 4 yellow
                results << PDNSResult.new('resolv', t2-t1, label, answer.to_s, rrtype.to_s, a.ttl, a_prev_time, Time.now, 1, 'white')
              end
            end
          rescue Timeout::Error => e
            $stderr.puts "#{self.class.name} lookup timed out: #{label}"
          end
        end
        results
      end
    end
  end
end
