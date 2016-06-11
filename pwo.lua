-- pwo protocol
pwo_proto = Proto("pwo","Pokemon World Offline protocol")

clientToServerPacketInfos = {
	 {"LOG", "Login"},
	 {"q",   "Movement"},
	 {"msg", "Send chat message"},
	 {"N",   "Interact with NPC"},
	 {"R",   "Answer to dialog"},
	 {"action", "Use battle action"},
	 {"npc", "Request NPCs"},
	 {"syn", "Request sync"}
}

serverToClientPacketInfos = {
	 {"Ref",   "Login result"},
	 {"msg",   "Chat message"},
	 {"E",     "Server time"},
	 {"Con",   "(?) Maps server"},
	 {"C",     "Chat channels"},
	 {"R",     "Dialog message"},
	 {"NPCCANCEL", "(?) Cancel NPC"},
	 {"mon",   "Pokemon Team update"},
	 {"sb",    "Start fight"},
	 {"a",     "Battle data"},
	 {"d",     "Inventory update"},
	 {"NPC",   "NPCs update"},
	 {"NB",    "Battlers NPCs update"},
	 {"q",     "Player position update"},
	 {"i",     "Player profile data"},
	 {"U",     "Another player update"}
}

local endOfPacket = [[|.\]] .. "\r\n"

function bindPacket(packetList, data)
	 local packetFound = false
	 local index = 1
	 local headersFound = {}
	 
	 while true do
			local matchStart, matchEnd, encryptedPacket = data.pwoData:find("(.-" .. endOfPacket .. ")", index)
			if encryptedPacket == nil then break end
			
			key = {
                0x0A, 0x6A, 0x36, 0x0E, 0x47, 0x70, 0x1F, 0x25, 0x41, 0x55, 0x1D, 0x0C, 0x23,
                0x10, 0x10, 0x3B, 0x5C, 0x68, 0x58, 0x63, 0x39, 0x57, 0x60, 0x16, 0x11, 0x14,
                0x48, 0x04, 0x35, 0x69, 0x63, 0x1A
            }

			x = 0
			y = 0
			j = 0
            box = {}
			
			packetLen = string.len(encryptedPacket) - 5
			halfLen = math.ceil(packetLen / 2)
			packet = ""

            for i = 0, 255 do
                box[i] = i
			end

            for i = 0, 255 do
				a1 = key[(i+1) % 32 + 1]
				a2 = box[i]
                j = (a1 + a2 + j) % 256
                x = box[i]
                box[i] = box[j]
                box[j] = x
			end

            j = 0

            for i = 0, packetLen-1 do
                y = (i+1) % 256
                j = (box[y] + j) % 256
                x = box[y]
                box[y] = box[j]
                box[j] = x

                d = box[(box[y] + box[j]) % 256]
				nc = bit.bxor(string.byte(encryptedPacket, i+1),d)
				if nc == 0 then
					nc = 1
				end
				packet = packet .. string.char(nc)
			end
			
			packet = string.reverse(packet)
			part1 = string.sub(packet, 1, halfLen)
			part2 = string.sub(packet, halfLen+1)
			packet = part2 .. part1
			lastbyte = string.byte(packet, packetLen)
			
			local localPacketFound = false
			for i, packetInfo in ipairs(packetList) do
				 if packet:find(packetInfo[1], 1, true) == 1 then
						data.tree:add(data.buffer(0,data.buffer:len() - 1),   "Description: " .. packetInfo[2])
						data.tree:add(data.buffer(0,packetInfo[1]:len() - 1), "Header:      " .. packetInfo[1])
						data.tree:add(data.buffer(0,packetInfo[1]:len() - 1), "Packet:      " .. packet)
						data.tree:add(data.buffer(0,packetInfo[1]:len() - 1), "LB:      " .. lastbyte)
						packetFound = true
						if headersFound[packetInfo[2]] == nil then
							 headersFound[packetInfo[2]] = 0
						end
						headersFound[packetInfo[2]] = headersFound[packetInfo[2]] + 1
						localPacketFound = true
						break
				 end
			end
			if localPacketFound == false then
				 data.tree:add("Packet: " .. packet)
				 if headersFound["UNKNOWN"] == nil then
						headersFound["UNKNOWN"] = 0
				 end
				 headersFound["UNKNOWN"] = headersFound["UNKNOWN"] + 1
			end
			index = matchEnd + 1
	 end

	 index = 1
	 for headerName, headerCount in pairs(headersFound) do
			if index ~= 1 then
				 data.infoField = data.infoField .. "|"
			end
			data.infoField = data.infoField .. headerName
			if headerCount > 1 then
				 data.infoField = data.infoField .. [[(x]] .. headerCount .. [[)]]
			end
			index = index + 1
	 end
	 return packetFound
end

-- create a function to dissect it
function pwo_proto.dissector(buffer,pinfo,tree)
	 pinfo.cols.protocol = "PWO"

	 local data = {
			buffer = buffer,
			pinfo = pinfo,
			pwoData = "",
			tree = tree:add(pwo_proto, buffer(), "PWO Protocol PwoData"),
			infoField = ""
	 }

	 local i = 0
	 while i < buffer:len() do
			data.pwoData = data.pwoData .. string.char(buffer(i,1):uint())
			i = i + 1
	 end
	 
	 local packetFound = false
	 if pinfo.src_port == 800 then
			data.infoField = "[s]"
			data.tree:add(buffer(0,buffer:len()), "server -> client")
			packetFound = bindPacket(serverToClientPacketInfos, data)
	 else
			data.infoField = "[c]"
			data.tree:add(buffer(0,buffer:len()), "client -> server")
			packetFound = bindPacket(clientToServerPacketInfos, data)
	 end
	 pinfo.cols.info = data.infoField;
	 data.tree:add(buffer(0,buffer:len() - 1), data.pwoData)
end
-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register our protocol to handle tcp port 800
tcp_table:add(800, pwo_proto)

