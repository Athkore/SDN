do

	local tunnel_proto = Proto("p4-tunnel","Tunnel Protocol Header")

	local t_id = ProtoField.uint16("tunnel_proto.tunnel_id", "Tunnel ID", base.HEX)
	local c_id = ProtoField.uint16("tunnel_proto.customer_id", "Customer ID", base.DEC)
	local e_type = ProtoField.uint16("tunnel_proto.etherType", "etherType", base.HEX)

	tunnel_proto.fields = {tunnel_id,customer_id,etherType}
	
	local ethernet_dissector
	function tunnel_proto.dissector(buffer,pinfo,tree)
		length = buffer:len()
		if length == 0 then return end
		pinfo.cols.protocol = tunnel_proto.name
		local subtree = tree:add(tunnel_proto, buffer(0,6), "p4 Tunnel ID Data")
		--local subtree = tree:add(tunnel_proto,buffer(),"Tunnel Protocol Header Data")
		--subtree:add(buffer(0,6),"Destination MAC: " .. buffer(0,6))
		--subtree:add(buffer(6,6),"Source MAC: " .. buffer(6,6))
		--subtree:add(buffer(12,2),"Type: " .. buffer(12,2))
		--subtree = subtree:add(buffer(14,20),"Tunnel Contents")
		--subtree:add(buffer(0,2),"Tunnel ID: " .. buffer(0,2):uint())
		--subtree:add(buffer(2,2),"Customer ID: " .. buffer(2,2):uint())
		--subtree:add(buffer(4,2),"Type: " .. buffer(4,2):uint())
		local tunnel_id = buffer(0,2)
		local customer_id = buffer(2,2)
		local etherType = buffer(4,2)

		subtree:add_le(tunnel_id, buffer(0,2), buffer(0,2))
		subtree:add_le(customer_id, buffer(2,2))
		subtree:add_le(etherType, buffer(4,2))

		ethernet_dissector:call(buffer, pinfo, tree)
	end

	--Dissector_add_uint("ethertype", 0x1212, tunnel_proto)
	--DissectorTable.heuristic_list()
	ethernet_table = DissectorTable.get("ethertype")
	ethernet_table:add(4626,tunnel_proto)

end
