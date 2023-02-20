function ipverify(ip_string)
{
    var c;
    var n = 0;
    var ch = ".0123456789"; 
    if (ip_string.length < 7 || ip_string.length > 15)
    return false; 
    for (var i = 0; i < ip_string.length; i++)
    {
        c = ip_string.charAt(i);
        if (ch.indexOf(c) == -1)
        return false; 
        else
        {
            if (c == '.')
            {
                if(ip_string.charAt(i+1) != '.')
                n++; 
                else return false;
            }
        } 
     }
     if (n != 3) 
     return false;
     if (ip_string.indexOf('.') == 0 || ip_string.lastIndexOf('.') == (ip_string.length - 1))
     return false;
     szarray = [0,0,0,0];
     var remain; 
     var i; 
     for(i = 0; i < 3; i++)
     {
        var n = ip_string.indexOf('.');
        szarray[i] = ip_string.substring(0,n);
        remain = ip_string.substring(n+1);
        ip_string = remain; 
     }
     szarray[3] = remain;
     for(i = 0; i < 4; i++)
     {
        if (szarray[i] < 0 || szarray[i] > 255)
        {
            return false; 
        }
    }
    return true; 
}      
function is_ipaddr(ip_string)
{ 
    if(ip_string.length == 0)
    {
        alert("请输入IP地址！"); 
        return false; 
    }
     if (!ipverify(ip_string))
     {
        alert("IP地址输入错误，请重新输入！");
        return false; 
     } 
     return true;
} 
function is_maskaddr(mask_string)
{
    if(mask_string.length == 0)
    {
        alert("请输入子网掩码（例如255.255.255.0）！"); 
        return false; 
    }
    if (!ipverify(mask_string))
    {
        alert("子网掩码输入错误，请重新输入（例如255.255.255.0）！");
        return false;
    }
    return true; 
} 
function is_gatewayaddr(gateway_string)
{
    if(gateway_string.length == 0)
    {
        alert("请输入网关！");
        return false;
    } 
    if (!ipverify(gateway_string))
    {
        alert("网关输入错误，请重新输入！");
        return false;
    }
        return true;
} 
function is_dnsaddr(dns_string)
{ 
    if(dns_string.length == 0)
    {
        alert("请输入DNS服务器！"); 
        return false; 
    }
    if (!ipverify(dns_string))
    {
        alert("DNS服务器输入错误，请重新输入！"); 
        return false;
    }
    return true;
} 
function macverify(mac_string)
{
	var c;
	var ch = "0123456789abcdef";
	var lcMac = mac_string.toLowerCase();
	
	if (lcMac == "ff-ff-ff-ff-ff-ff")
	{
		return false;
	}
	
	if (lcMac == "00-00-00-00-00-00")
	{
		return false;
	}
	
	if (mac_string.length != 17)
	{
		return false;
	}
	for (var i = 0; i < lcMac.length; i++)
    {
		c = lcMac.charAt(i);
		if (i % 3 == 2)
		{
			if(c != '-')
			{
				return false;
			}
		}
		else if (ch.indexOf(c) == -1)
        {
			return false;
        }
	}
	c = lcMac.charAt(1);
	if (ch.indexOf(c) % 2 == 1)
	{
		return false;
	}	
	return true;
} 
function is_macaddr(mac_string)
{
    if(mac_string.length == 0)
    {
        alert("请输入MAC地址！");
        return false;
     } 
     if (!macverify(mac_string))
     {
        alert("MAC地址输入错误，请重新输入！");
        return false; 
     } 
     return true; 
}
function is_number(num_string,nMin,nMax)
{
    var c;
    var ch = "0123456789";
    for (var i = 0; i < num_string.length; i++)
    {
        c = num_string.charAt(i); 
        if (ch.indexOf(c) == -1) 
        return false; 
    }
    if(parseInt(num_string,10) < nMin || parseInt(num_string,10) > nMax)
    return false;
    return true; 
} 
function lastipverify(lastip,nMin,nMax)
{
    var c;
    var n = 0;
    var ch = "0123456789";
    if(lastip.length = 0) 
    return false; 
    for (var i = 0; i < lastip.length; i++)
    {
        c = lastip.charAt(i);
        if (ch.indexOf(c) == -1) 
        return false; 
    }
    if (parseInt(lastip,10) < nMin || parseInt(lastip,10) > nMax)
    return false;
    return true;
} 
function is_lastip(lastip_string,nMin,nMax)
{
    if(lastip_string.length == 0)
    {
        alert("请输入IP地址（1－254）！");
        return false;
    } 
    if (!lastipverify(lastip_string,nMin,nMax))
    {
        alert("IP地址输入错误，请重新输入（1－254）！");
        return false;
    } 
    return true;
} 
function is_domain(domain_string)
{
    var c; var ch = "-.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; 
    for (var i = 0; i < domain_string.length; i++)
    {
        c = domain_string.charAt(i);
        if (ch.indexOf(c) == -1)
        { 
            alert("输入中含有非法字符，请重新输入！");
            return false; 
        }
    } 
    return true; 
 }
 
function portverify(port_string){
	var c;
	var ch = "0123456789";
	if(port_string.length == 0)
		return false;
	for (var i = 0; i < port_string.length; i++){
		c = port_string.charAt(i);
		if (ch.indexOf(c) == -1)
			return false;
	}
	if (parseInt(port_string,10) <= 0 || parseInt(port_string,10) > 65535)
		return false;
	return true;
}
function is_port(port_string)
{
    if(port_string.length == 0)
    {
        alert("请输入端口地址 ( 1-65535 ) ！");
        return false;
    }
    if (!portverify(port_string))
    {
        alert("端口地址输入超出合法范围，请重新输入( 1-65535 ）！"); 
        return false;
    }
        return true;
} 
function charCompare(szname,limit){
	var c;
	var l=0;
	var ch = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@^-_.><,[]{}?/+=|\\'\":;~!#$%()` & ";
	if(szname.length > limit)
		return false;
	for (var i = 0; i < szname.length; i++){
		c = szname.charAt(i);
		if (ch.indexOf(c) == -1){
			l += 2;
		}
		else
		{
			l += 1;
		}
		if ( l > limit)
		{
			return false;
		}
	}
	return true;
}
function is_hostname(name_string, limit){
	if(!charCompare(name_string,limit)){
		alert("您最多只能输入%s个英文字符，一个汉字等于两个英文字符，请重新输入！".replace('%s',limit));
		return false;
	}
	else
		return true;
}
function is_digit(num_string)
{ 
    var c; 
    var ch = "0123456789"; 
    for(var i = 0; i < num_string.length; i++)
    {
        c = num_string.charAt(i); 
        if (ch.indexOf(c) == -1)
        {        
            return false; 
        }
    }
    return true;
}

function disableTag(obj, tag, type)
{
	try
	{
		var items = obj.getElementsByTagName(tag);
	}
	catch(e)
	{
		return;
	}
	if (type == undefined)
	{
		for (var i = 0; i < items.length; i++)
		{
			items[i].disabled = true;
		}
	}
	else
	{
		for (var i = 0; i < items.length; i++)
		{
			if (items[i].type == type)
				items[i].disabled = true;
		}		
	}
}

function enableTag(obj, tag, type)
{
	try
	{
		var items = obj.getElementsByTagName(tag);
	}
	catch(e)
	{
		return;
	}
	if (type == undefined)
	{
		for (var i = 0; i < items.length; i++)
		{
			items[i].disabled = false;
		}
	}
	else
	{
		for (var i = 0; i < items.length; i++)
		{
			if (items[i].type == type)
				items[i].disabled = false;
		}		
	}
}

/*added by ZQQ, 2011.12.24*/
function checkIpAddressFormat(address) { 
   var i = 0, num = 0;
   var blankNum = 0;	/* the number of  "::" symbol */

   var patten = /[^a-fA-F0-9:]/ig;

   if (address.match(patten) != null)
	  return false;

	if (address.indexOf(":::") != -1)
	{
		return false;
	}

   addrParts = address.split(':');
   	
   if (addrParts.length < 3 || addrParts.length > 8)
      return false;

   for (i = 0; i < addrParts.length; i++) 
   {
   	  if (addrParts[i].length > 4)	/* the length of each part can be 0~4, that is both "::" and ":234:" is OK. */
	  	 return false;
      if (addrParts[i] != "")
      {
         if (i == 8)
		 	return false;
      }
	  else 
	  {
	     if ((i != 0) && (i != (addrParts.length - 1)))	/* only one "::" symbol is allow. */
	  	    blankNum += 1;
	  	 
	  	 if (blankNum > 1)
	  	 {	
	  	 	return false;
	  	 }
	  }
   }

   if (blankNum == 0)	/* if the address dost't contain "::" symbol to decrease the length, 8 parts are need to write. */
   {
      if (addrParts.length != 8)
	     return false;
   }
   else
   {
      if (addrParts.length > 9)	/* if the address contain "::" symbol, the number of parts need to be no more than 9. */
		 return false;
   }
   
   return true;
}


function isValidIPv6Prefix(prefix)
{
	var addrparts;
	var num;
	var patten = /[^a-fA-F0-9:]/ig;
	var val = 0;
	var i = 0;
	
	if(prefix.length == 0)
	{
		alert("空白前缀，请输入一个有效IPv6地址前缀。");
		return false;
	}
	if (prefix.indexOf(":::") != -1)
	{
		alert("\"" + prefix + "\"" + " 是一个无效的IPv6地址前缀格式，请检查。");
		return false;
	}
	
	if (prefix.match(patten) != null)
	{
		alert("\"" + prefix + "\"" + " 含有非法字符，请检查。");
		return false;
	}

	if (prefix.charAt(prefix.length - 1) != ":" || prefix.charAt(prefix.length - 2) != ":")
	{
		alert("\"" + prefix + "\"" + " 是一个无效的IPv6地址前缀格式，请检查。");
		return false;
	}
	addrParts = prefix.split('::');

	if (addrParts.length >=3)
	{
		alert("\"" + prefix + "\"" + " 不应该含有多于两个 \"::\"，请检查。");
		return false;
	}
	
   addrParts = prefix.split(':');
   if(addrParts.length >= 7 || addrParts.length < 3)
   {
		alert("\"" + prefix + "\"" + " 不是一个有效的IPv6地址前缀格式，请检查。");
		return false;
   }
 
	for(i = 0; i <addrParts.length; i++)
	{
		if(addrParts[i].length > 4)
		{
			alert("\"" + prefix + "\"" + " 含有无效部分 "+ addrParts[i] + "，请检查。");
			return false;
		}
	}
	
	val = parseInt(addrParts[0], 16);
	
	if (val >> 13 != 0x001)
   {
		alert("\"" + prefix + "\"" + " 不是一个IPv6地址前缀，请检查。");
		return false;
   }
	
	/*
	if (addrParts.length > 1)
	{
		if (0x2001 == val && 0x0db8 == parseInt(addrParts[1], 16))
   {
			alert("\"" + prefix + "\"" + " is a reserved public IPv6 address prefix, please fill up a valid address.");
		return false;
   }
	}
	*/
	
	if (0x2D00 == val || 0x2E00 == val || 0x3000 == val)
	{
		alert("\"" + prefix + "\"" + " 是一个保留的公有IPv6地址前缀，请输入一个有效的地址。");
		return false;
	}
	
	/*
	if (0x3ffe == val)
	{
		alert("\"" + prefix + "\"" + " is an unused public IPv6 address prefix, please fill up a valid address.");
		return false;
	}
	*/
	
	return true;
}

function isGlobalUnicastAddressesPrefix(address)
{
	var addrparts;
	var num;
	var val = 0;
	addrParts = address.split(':');
	val = parseInt(addrParts[0], 16) >> 13;

	if (val != 0x001)
		return false;
	else
		return true;
}

function isPubIPv6Addr(address){
	var addrparts;
	var num;
	var patten = /[^a-fA-F0-9:]/ig;
	var val = 0;
	
   addrParts = address.split(':');

	/* check ::1/128 ::/128 ::/0 */
	if (addrParts[0] == "" & addrParts[1] == "")
	{	
		if (addrParts.length == 2)
		{
			return false;							/* ::/128 ::/0 */
		}
		
		if (parseInt(addrParts[2],16) == 1)
		{
			return false;							/* ::1/128 */
		}
			
		if (parseInt(addrParts[2], 16) == 0xFFFF)
		{
			return false;
	}
	}
	
	if (addrParts[addrParts.length - 1] == "" && addrParts[addrParts.length - 2] =="")
   {
		return false;
   }
	
	val = parseInt(addrParts[0], 16);
	if (val == 0x0100 || val == 0x0200 || val == 0x0400 || val ==0x0800 || val == 0x1000 || (val >= 0x4000 && val <= 0xC000) || val == 0xE000
	|| val == 0xF000 || val == 0xf800 || val == 0xFC00 || val == 0xFE00 || val == 0xFE80 || val == 0xFEC0 || val == 0xFF00)
	{
		return false;
	}
	
	if ((parseInt(addrParts[0], 16) >> 6) == 0x5f00)
	{
		return false;
	}
		
	/*
	if ((parseInt(addrParts[0], 16) >> 6) == 0x3ffe)
	{
		return false;
	}
	*/
	
	/* check fe80::/10 */
	if ((parseInt(addrParts[0], 16) >> 6) == 0x3fa)
	{
		return false;
	}
	
	/* check fc00::/7 */
	if ((parseInt(addrParts[0], 16) >> 9) == 0x7e )
	{
		return false;
	}
	
	/* check 2001:db8::/32 */
	//if (parseInt(addrParts[0], 16) == 0x2001 & parseInt(addrParts[1], 16) == 0xdb8 )
	//	return false;
	
	/* check 2001:10::/28 */
	//if (parseInt(addrParts[0], 16) == 0x2001 & (parseInt(addrParts[1], 16) >> 4) == 1 )
	//	return false;
		
	/* check ff00::/8 */
	if ((parseInt(addrParts[0], 16) >> 8) == 0xff)
	{
		return false;
	}
		
	/* check 64:ff9b::/96  
	 * three condition 64:ff9b::xxxx/96 64:ff9b::xxxx:xxxx/96 64:ff9b::/96*/
	if (parseInt(addrParts[0], 16) == 0x64 & parseInt(addrParts[1], 16) == 0xff9b & addrParts[2] == "")
	{
		if (addrParts.length <= 5)
		{
			return false;
	}
	}
		 
	return true;
}

function isReservedIpAddress(address)
{
	/*check the IP is reserverd ip address*/
	var addrparts;
	var num;
	var val = 0;
	addrParts = address.split(':');
	
	/*http://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xml*/
	/*2001:db8/32 documentation-only prefix  in the IPv6*/
	/* IPv6 Ready Logo is need this address
	val = parseInt(addrParts[0], 16);
	if (0x2001 == val && 0x0db8 == parseInt(addrParts[1], 16))
	{
		return true;
	}
	*/
	val = parseInt(addrParts[0], 16);
	if (0x2D00 == val || 0x2E00 == val || 0x3000 == val)
	{
		return true;
	}
	return false;
}
 
function isUnusedIpAddress(address)
{
	var addrparts;
	var num;
	var val = 0;
	addrParts = address.split(':');
	val = parseInt(addrParts[0], 16);
	/* ipv6 logo test need this ip
	if (0x3ffe == val)
	{
		return true;
	}
	*/
	return false;
}

function isGlobalIPv6Addr(address)
{
	if (false == checkIpAddressFormat(address))
	{
		alert("\"" + address + "\"" + " 不是一个IPv6地址，请输入一个有效的地址。");
		return false;
	}
	else if (false == isPubIPv6Addr(address))
	{
		alert("\"" + address + "\"" + " 不是一个公有IPv6地址，请输入一个有效的地址。");
		return false;
	}
	else if (false == isGlobalUnicastAddressesPrefix(address))
	{
		alert("\"" + address + "\"" + " 不是一个公有IPv6地址，请输入一个有效的地址。");
		return false;
	}
	else if (true == isReservedIpAddress(address))
	{
		alert("\"" + address + "\"" + " 是一个保留的公有IPv6地址，请输入一个有效的地址。");
		return false;
	}
	else if (true == isUnusedIpAddress(address)) 
	{
		alert("\"" + address + "\"" + " 是一个不用的IPv6地址，请输入一个有效的地址。");
		return false;
	}
	
	return true;

}
	
