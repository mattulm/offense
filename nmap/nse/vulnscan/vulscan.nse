description = [[

INTRODUCTION

Vulscan is a module which enhances nmap to a vulnerability scanner. The
nmap option -sV enables version detection per service which is used to
determine potential flaws according to the identified product. The data
is looked up in an offline version scip VulDB.

INSTALLATION

Please install the files into the following folder of your Nmap
installation:

   Nmap\scripts\vulscan\*

USAGE

You have to run the following minimal command to initiate a simple
vulnerability scan:

   nmap -sV --script=vulscan/vulscan.nse www.example.com

VULNERABILITY DATABASE

There are the following pre-installed databases available at the
moment:

   scipvuldb.csv       | http://www.scip.ch/en/?vuldb
   cve.csv             | http://cve.mitre.org
   osvdb.csv           | http://www.osvdb.org (outdated, 02/03/2011)
   securityfocus.csv   | http://www.securityfocus.com/bid/
   securitytracker.csv | http://www.securitytracker.com

SINGLE DATABASE MODE

You may execute vulscan with the following argument to use a single
database:

   --script-args "vulscandb=your_own_database"

It is also possible to create and reference your own databases. This
requires to create a database file, which has the following structure:

   <id>;<title>

Just execute vulscan like you would by refering to one of the pre-
delivered databases. Feel free to share your own database and
vulnerability connection with me, to add it to the official
repository.

UPDATE DATABASE

If you want to upgrade your database, go to the scip web site and
download the current entries:

   http://www.scip.ch/vuldb/scipvuldb.csv

Copy the full list into the existing database:

   /vulscan/scipvuldb.csv

INTERACTIVE MODE

The interactive mode helps you to override version detection results
for every port. Use the following argument to enable the interactive
mode:

   --script-args "vulscaninteractive=1"

REPORTING

All matching results are printed one by line. The default layout for
this is:

   [{id}] {title}\n

You may enforce your own report structure by using the following
argument:

   --script-args "vulscanoutput='{id} - Title: {title} ($matches})\n'"

Supported are the following elements for a dynamic report template:

   {id}      ID of the vulnerability
   {title}   Title of the vulnerability
   {matches} Count of matches
   \n        Newline
   \t        Tab

DISCLAIMER

Keep in mind that this kind of derivative vulnerability scanning
heavily relies on the confidence of the version detection of nmap, the
amount of documented vulnerebilities and the accuracy of pattern
matching. The existence of potential flaws is not verified with
additional scanning nor exploiting techniques.

]]

--@output
-- PORT   STATE SERVICE REASON  VERSION
-- 25/tcp open  smtp    syn-ack Exim smtpd 4.69
-- | osvdb (22 findings):
-- | [2440] qmailadmin autorespond Multiple Variable Remote Overflow
-- | [3538] qmail Long SMTP Session DoS
-- | [5850] qmail RCPT TO Command Remote Overflow DoS
-- | [14176] MasqMail Piped Aliases Privilege Escalation

--@changelog
-- v1.0 | 06/18/2013 | Marc Ruef | Dynamic report structures
-- v0.8 | 06/17/2013 | Marc Ruef | Multi-database support
-- v0.7 | 06/14/2013 | Marc Ruef | Complete re-write of search engine
-- v0.6 | 05/22/2010 | Marc Ruef | Added interactive mode for guided testing
-- v0.5 | 05/21/2010 | Marc Ruef | Seperate functions for search engine
-- v0.4 | 05/20/2010 | Marc Ruef | Tweaked analysis modules
-- v0.3 | 05/19/2010 | Marc Ruef | Fuzzy search for product names included
-- v0.2 | 05/18/2010 | Marc Ruef | Uniqueness of found vulnerabilities
-- v0.1 | 05/17/2010 | Marc Ruef | First alpha running basic identification

--@bugs
-- Fuzzy search is sometimes catching wrong products

--@todos
-- Take port.version.version / object_versions into account
-- Create product lookup table to match nmap<->db
-- Enhance nmap/db to be CPE compliant (http://cpe.mitre.org)
-- Display of identification confidence (e.g. +full_match, -partial_match)
-- Add support for user arguments to change scan and search behavior
-- Add auto-update feature for osvdb database (download & install)

--@thanks
-- I would like to thank a number of people which supported me in
-- developing this script: Stefan Friedli, Simon Zumstein, Sean Rütschi,
-- David Fifield, Doggy Dog and Matt Brown.

author = "Marc Ruef, marc.ruef-at-computec.ch, http://www.computec.ch/mruef/"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

local stdnse = require("stdnse")

portrule = function(host, port)
	if port.version.product ~= nil and port.version.product ~= "" then
		return true
	else
		stdnse.print_debug(1, "vulscan: No version detection data available. Analysis not possible.")
	end
end

action = function(host, port)
	local product = port.version.product
	local outputstructure = "[{id}] {title}\n"
	local database = {}
	local vulnerabilities_matches = {}
	local vulnerabilities_matches_count = 0
	local result = ""

	stdnse.print_debug(1, "vulscan: Found service " .. port.version.product)

	--Go into interactive mode
	if nmap.registry.args.vulscaninteractive == "1" then
		stdnse.print_debug(1, "vulscan: Enabling interactive mode ...")
		print("The scan has determined the following product:")
		print(product)
		print("Press Enter to accept. Define new string to override.")
		local product_override = io.stdin:read'*l'

		if string.len(product_override) ~= 0 then
			product = product_override
			stdnse.print_debug(1, "vulscan: Product overwritten as " .. product)
		end
	end

	if nmap.registry.args.vulscanoutput ~= nil then
		outputstructure = nmap.registry.args.vulscanoutput
	end

	if nmap.registry.args.vulscandb then
		stdnse.print_debug(1, "vulscan: Using single mode db " .. nmap.registry.args.vulscandb .. " ...")
		vulnerabilities_matches = find_vulnerabilities(product, nmap.registry.args.vulscandb)
		vulnerabilities_matches_count = #vulnerabilities_matches
		if vulnerabilities_matches_count > 0 then
			result = result .. nmap.registry.args.vulscandb .. " (" .. vulnerabilities_matches_count .. " findings):\n" ..
					prepare_result(vulnerabilities_matches, outputstructure) .. "\n\n"
		end
	else
		--Add your own database, if you want to include it in the multi db mode
		database[1] = {file="scipvuldb.csv",			url="http://www.scip.ch/en/?vuldb"}
		database[2] = {file="cve.csv",					url="http://cve.mitre.org"}
		database[3] = {file="osvdb.csv",				url="http://www.osvdb.org"}
		database[4] = {file="securityfocus.csv",		url="http://www.securityfocus.com/bid/"}
		database[5] = {file="securitytracker.csv",		url="http://www.securitytracker.com"}

		stdnse.print_debug(1, "vulscan: Using multi db mode (" .. #database .. " databases) ...")
		for i,v in ipairs(database) do
			vulnerabilities_matches_count = 0
			vulnerabilities_matches = find_vulnerabilities(product, v.file)

			vulnerabilities_matches_count = vulnerabilities_matches_count + #vulnerabilities_matches
			result = result .. v.file:gsub(".csv", "") .. " - " .. v.url .. " (" .. vulnerabilities_matches_count .. " findings):\n"
			if #vulnerabilities_matches > 0 then
					result = result .. prepare_result(vulnerabilities_matches, outputstructure) .. "\n"
			else
					result = result .. "No findings\n\n"
			end
		end
	end

	if result then
		stdnse.print_debug(1, "vulscan: " .. vulnerabilities_matches_count .. " vulnerabilities found")
		return result
	end
end

function find_vulnerabilities(product, database)
	local product_string = ""
	local vulnerabilities = ""
	local vulnerabilities_matches = {}
	local vulnerabilities_id
	local vulnerabilities_title
	local vulnerabilities_found

	--Load the database
	vulnerabilities = read_from_file("scripts/vulscan/" .. database)

	--Clean useless dataparts (speeds up search and improves accuracy)
	product_string = product:gsub(" httpd", "")
	product_string = product_string:gsub(" smtpd", "")
	product_string = product_string:gsub(" ftpd", "")

	local products_words = stdnse.strsplit(" ", product_string)

	stdnse.print_debug(1, "vulscan: Starting search of " .. product_string ..
		" in " .. database ..
		" (" .. #vulnerabilities .. " entries) ...")

	--Iterate through the vulnerabilities in the database
	for i=1, #vulnerabilities, 1 do
		vulnerabilities_id		= extract_value_from_table(vulnerabilities[i], 1, ";")
		vulnerabilities_title	= extract_value_from_table(vulnerabilities[i], 2, ";")

		if type(vulnerabilities_title) == "string" then
			--Find the matches for the database entry
			for j=1, #products_words, 1 do
				vulnerabilities_found = string.find(string.lower(vulnerabilities_title), escape(string.lower(products_words[j])), 1)
				if type(vulnerabilities_found) == "number" then
					--Initiate table
					if vulnerabilities_matches[#vulnerabilities_matches] == nil then
						vulnerabilities_matches[#vulnerabilities_matches] = {
							id		= vulnerabilities_id,
							title	= vulnerabilities_title,
							matches	= 1
						}
					--Create new entry
					elseif vulnerabilities_matches[#vulnerabilities_matches].id ~= vulnerabilities_id then
						vulnerabilities_matches[#vulnerabilities_matches+1] = {
							id		= vulnerabilities_id,
							title	= vulnerabilities_title,
							matches	= 1
						}
					--Add to current entry
					else
						vulnerabilities_matches[#vulnerabilities_matches] = {
							id		= vulnerabilities_id,
							title	= vulnerabilities_title,
							matches	= vulnerabilities_matches[#vulnerabilities_matches].matches+1
						}
					end

					stdnse.print_debug(1, "vulscan: Match id " .. vulnerabilities_id ..
						" with match no. " .. vulnerabilities_matches[#vulnerabilities_matches].matches ..
						" (" .. products_words[j] .. ")")
				end
			end
		end
	end

	return vulnerabilities_matches
end

function prepare_result(vulnerabilities_matches, outputstructure)
	local grace = 0
	local line = ""
	local result = ""

	--Search the entries with the best matches
	if #vulnerabilities_matches > 0 then
		for matchpoints=5, 1, -1 do
			for i=1, #vulnerabilities_matches, 1 do
				if vulnerabilities_matches[i].matches == matchpoints then
					stdnse.print_debug(2, "vulscan: Setting up result id " .. i)
					result = result .. report_parsing(vulnerabilities_matches[i], outputstructure)
				end
			end

			if result ~= "" then			
				-- if the next iteration shall be approached (increases matches)
				if grace == 0 then
					stdnse.print_debug(2, "vulscan: Best matches found in 1st pass. Going to use 2nd pass ...")
					grace = grace+1
				else
					break
				end
			end
		end
	end

	if result ~= "" then
		return result
	end
end

function report_parsing(vulnerability, outputstructure)
	local data = outputstructure

	--vulnerability data
	data = data:gsub("{id}", vulnerability.id)
	data = data:gsub("{title}", vulnerability.title)
	data = data:gsub("{matches}", vulnerability.matches)

	--layout elements
	data = data:gsub("\\n", "\n")
	data = data:gsub("\\t", "\t")

	return data
end

function extract_value_from_table(tableline, column, delimiter)
	local values = stdnse.strsplit(delimiter, tableline)

	if type(values[column]) == "string" then
		return values[column]
	end
end

function read_from_file(file)
	local filepath = nmap.fetchfile(file)

	if filepath then
		local f, err, _ = io.open(filepath, "r")
		if not f then
			stdnse.print_debug(1, "vulscan: Failed to open file" .. file)
		end

		local line, ret = nil, {}
		while true do
			line = f:read()
			if not line then break end
			ret[#ret+1] = line
		end

		f:close()

		return ret
	else
		stdnse.print_debug(1, "vulscan: File " .. file .. " not found")
		return ""
	end
end

function escape(str)
	local escape_characters = { "%(", "%)", "%.", "%%", "%+", "%-", "%*", "%?", "%[", "%]", "%^", "%$" }

	for i=1, #escape_characters, 1 do
		str = string.gsub(str, escape_characters[i], "%" .. escape_characters[i])
	end

	return str
end
