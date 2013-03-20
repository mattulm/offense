
<!-- saved from url=(0061)http://seclists.org/nmap-dev/2012/q1/att-662/rdp-ms12-020.nse -->
<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"></head><body><pre style="word-wrap: break-word; white-space: pre-wrap;">description = [[
Checks if a machine is vulnerable to ms12-020 RDP vulnerability.

Microsoft bulletin ms12-020 patches two vulnerabilities.
CVE-2012-0152 which addresses a DoS vulnerability inside Terminal Server,
and CVE-2012-0002 which fixes a vulnerability in Remote Desktop Protocol.
Both are part of Remote Desktop Services. 

Script works by checking for a CVE-2012-0152 vulnerability.
Patched and unpatched system differ in the results from which
we can conclude if the service is vulnerable or not.


References:
http://technet.microsoft.com/en-us/security/bulletin/ms12-020
http://support.microsoft.com/kb/2621440
http://zerodayinitiative.com/advisories/ZDI-12-044/
http://aluigi.org/adv/termdd_1-adv.txt

Original check by by Worawit Wang (sleepya)
]]

-- @output
-- PORT     STATE SERVICE
-- 3389/tcp open  ms-wbt-server
-- | rdp-ms12-020:
-- |   VULNERABLE:
-- |   MS12-020 Remote Desktop Protocol Vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2012-0152,CVE-2012-0002
-- |     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
-- |     Description:
-- |               Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system.
-- |
-- |     Disclosure date: 2012-03-13
-- |     References:
-- |       http://technet.microsoft.com/en-us/security/bulletin/ms12-020
-- |_      http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0152,CVE-2012-0002

author = "Aleksandar Nikolic, based on python script by sleepya"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln"}

require "shortport"
require "stdnse"
require "vulns"

portrule = shortport.port_or_service({3389},{"ms-wbt-server"})

action = function(host, port)
	local socket = nmap.new_socket()
	local status, err,response
	
	-- see http://msdn.microsoft.com/en-us/library/cc240836%28v=prot.10%29.aspx for more info 
	local connectionRequestStr = "0300" -- TPKT Header version 03, reserved 0
						.. "0013" -- Length
						.. "0e"   -- X.224 Data TPDU length
						.. "e0"	  -- X.224 Type (Connection request)
						.. "0000" -- dst reference
						.. "0000" -- src reference
						.. "00" -- class and options
						.. "01" -- RDP Negotiation Message
						.. "00" -- flags
						.. "0800" -- RDP Negotiation Request Length
						.. "00000000" --RDP Negotiation Request
	local connectionRequest = bin.pack("H",connectionRequestStr)
	
	-- see http://msdn.microsoft.com/en-us/library/cc240836%28v=prot.10%29.aspx
	local connectInitialStr = "03000065" -- TPKT Header
				.. "02f080" -- Data TPDU, EOT
				.. "7f655b" -- Connect-Initial
				.. "040101" -- callingDomainSelector
				.. "040101" -- calledDomainSelector
				.. "0101ff" -- upwardFlag
				.. "3019" -- targetParams + size
					..  "020122" -- maxChannelIds
					..	"020120" -- maxUserIds
					..	"020100" -- maxTokenIds
					..	"020101" -- numPriorities
					..	"020100" -- minThroughput
					..	"020101" -- maxHeight
					..	"0202ffff" -- maxMCSPDUSize
					..	"020102" -- protocolVersion
				.. "3018" -- minParams + size 
					.. "020101" -- maxChannelIds
					.. "020101" -- maxUserIds
					.. "020101" -- maxTokenIds
					.. "020101" -- numPriorities
					.. "020100" -- minThroughput
					.. "020101" -- maxHeight
					.. "0201ff" -- maxMCSPDUSize
					.. "020102" -- protocolVersion
				.. "3019" -- maxParams + size
					.. "0201ff" -- maxChannelIds
					.. "0201ff" -- maxUserIds
					.. "0201ff" -- maxTokenIds
					.. "020101" -- numPriorities
					.. "020100" -- minThroughput
					.. "020101" -- maxHeight
					.. "0202ffff" -- maxMCSPDUSize
					.. "020102" -- protocolVersion
				.. "0400" -- userData
	local connectInitial = bin.pack("H",connectInitialStr)
	
	-- see http://msdn.microsoft.com/en-us/library/cc240835%28v=prot.10%29.aspx
	local userRequestStr = "0300" -- header
						.. "0008" -- length
						.. "02f080" -- X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
						.. "28" -- PER encoded PDU contents
	local userRequest = bin.pack("H",userRequestStr)
	
	local user1,user2
	local pos

	local rdp_vuln = {
	title = "MS12-020 Remote Desktop Protocol Vulnerability",
	IDS = {CVE = 'CVE-2012-0152,CVE-2012-0002'},
	risk_factor = "High",
	scores = {
	  CVSSv2 = "9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)",
	},
	description = [[
	Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system. 
	]],
	references = {
	  'http://technet.microsoft.com/en-us/security/bulletin/ms12-020',
	},
	dates = {
	  disclosure = {year = '2012', month = '03', day = '13'},
	},
	exploit_results = {},
	}
	
	local report = vulns.Report:new(SCRIPT_NAME, host, port)
	rdp_vuln.state = vulns.STATE.NOT_VULN

	socket:connect(host.ip, port)
	status, err = socket:send(connectionRequest)
	
	status, response = socket:receive_bytes(0)
	if response ~= bin.pack("H","0300000b06d00000123400") then
		-- probably not rdp at all 
		return report:make_output(rdp_vuln) 
	end

	status, err = socket:send(connectInitial) 
	status, err = socket:send(userRequest)  -- send attach user request
	status, response = socket:receive_bytes(0) -- recieve attach user confirm 
	pos,user1 = bin.unpack("&gt;S",response:sub(10,11)) -- user_channel-1001 - see http://msdn.microsoft.com/en-us/library/cc240918%28v=prot.10%29.aspx
	
	status, err = socket:send(userRequest) -- send another attach user request
	status, response = socket:receive_bytes(0) -- recieve another attach user confirm
	pos,user2 = bin.unpack("&gt;S",response:sub(10,11)) -- second user's channel - 1001
	user2 = user2+1001 -- second user's channel 
	data4 = bin.pack("&gt;SS",user1,user2)
	data5 = bin.pack("H","0300000c02f08038") -- channel join request TPDU 
	channelJoinRequest = data5 .. data4
	status, err = socket:send(channelJoinRequest) -- bogus channel join request user1 requests channel of user2 
	status, response = socket:receive_bytes(0)
	if response:sub(8,9) == bin.pack("H","3e00") then
		-- 3e00 indicates a successfull join 
		-- see http://msdn.microsoft.com/en-us/library/cc240911%28v=prot.10%29.aspx
		-- service is vulnerable
		-- send a valid request to prevent the BSoD
		data4 = bin.pack("&gt;SS",user2-1001,user2)
		channelJoinRequest = data5 .. data4 -- valid join request
		status, err = socket:send(channelJoinRequest)
		status, response = socket:receive_bytes(0)
		socket:close()
		rdp_vuln.state = vulns.STATE.VULN
		return report:make_output(rdp_vuln)
	end
	--service is not vulnerable
	socket:close()
	return report:make_output(rdp_vuln)
end
</pre></body></html>