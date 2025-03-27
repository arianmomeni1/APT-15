/*
  APT15 = Mirage = Ke3chang 
*/
rule clean_apt15_patchedcmd {
	meta:
		author = "Arian Seyed Momen"
		description = "This is a patched CMD. This is the CMD that RoyalCli uses."
		sha256 = "90d1f65cfa51da07e040e066d4409dc8a48c1ab451542c894a623bc75c14bf8f"
	strings:
		$cmd1 = "eisableCMD" wide
		$cmd2 = "%WINDOWS_COPYRIGHT%" wide
		$cmd3 = "Cmd.Exe" wide
		$cmd4 = "Windows Command Processor" wide
	condition:
		all of them
}

rule malware_apt15_royalcli_1 {
	meta:
		author = "Arian Seyed Momen"
		description = "Generic strings found in the Royal CLI tool"
		sha256 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"
	strings:
		$tmp1 = "%s~clitemp%08x.tmp" fullword
		$tmp2 = "qg.tmp" fullword
		$tmp3 = "%s /c %s>%s" fullword
		$tmp4 = "hkcmd.exe" fullword
		$tmp5 = "%snewcmd.exe" fullword
		$tmp6 = "%shkcmd.exe" fullword
		$tmp7 = "%s~clitemp%08x.ini" fullword
		$obj1 = "myRObject" fullword
		$obj2 = "myWObject" fullword
	condition:
		5 of them
}

rule malware_apt15_royalcli_2 {
	meta:
		author = "Arian Seyed Momen"
		description = "APT15 RoyalCli backdoor"
	strings:
		$royal1 = "%shkcmd.exe" fullword
		$royal2 = "myRObject" fullword
		$royal3 = "%snewcmd.exe" fullword
		$royal4 = "%s~clitemp%08x.tmp" fullword
		$royal5 = "hkcmd.exe" fullword
		$royal6 = "myWObject" fullword
	condition:
		uint16(0) == 0x5A4D and 2 of them
}

rule malware_apt15_bs2005 {
	meta:
		author = "Arian Seyed Momen"
		md5 = "ed21ce2beee56f0a0b1c5a62a80c128b"
		description = "APT15 bs2005"
	strings:
		$bs1 = "%s&%s&%s&%s" wide ascii
		$bs2 = "%s\\%s" wide ascii
		$bs3 = "WarOnPostRedirect" wide ascii fullword
		$bs4 = "WarnonZoneCrossing" wide ascii fullword
		$bs5 = "IEharden" wide ascii fullword
		$regex = /"?%s\s*"?\s*\/C\s*"?%s\s*>\s*\\?"?%s\\(\w+\.\w+)?"\s*2>&1\s*"?/
	condition:
		(uint16(0) == 0x5A4D and 5 of them) or 
		(uint16(0) == 0x5A4D and 3 of them and 
			(pe.imports("advapi32.dll", "CryptDecrypt") and 
			 pe.imports("advapi32.dll", "CryptEncrypt") and
			 pe.imports("ole32.dll", "CoCreateInstance"))
		)
}

rule malware_apt15_royaldll {
	meta:
		author = "Arian Seyed Momen"
		description = "DLL implant, originally rights.dll and runs as a service"
		sha256 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
	strings:
		$svc1 = "Nwsapagent" fullword
		$svc2 = "\"%s\">>\"%s\"\\s.txt"
		$svc3 = "del c:\\windows\\temp\\r.exe /f /q"
		$svc4 = "del c:\\windows\\temp\\r.ini /f /q"
	condition:
		3 of them
}

rule malware_apt15_exchange_tool {
	meta:
		author = "Arian Seyed Momen"
		md5 = "d21a7e349e796064ce10f2f6ede31c71"
		description = "This is an Exchange enumeration/hijacking tool used by APT15"
	strings:
		$exch1 = "subjectname" fullword
		$exch2 = "sendername" fullword
		$exch3 = "WebCredentials" fullword
		$exch4 = "ExchangeVersion" fullword
		$exch5 = "EnumMail" fullword
		$exch6 = "EnumFolder" fullword
		$exch7 = "/list" wide
		$exch8 = "/enum" wide
		$exch9 = "/save" wide
	condition:
		uint16(0) == 0x5A4D and 7 of them
}

rule malware_apt15_generic {
	meta:
		author = "Arian Seyed Momen"
		description = "Find generic data potentially relating to APT15 tools"
	strings:
		$gen1 = "myWObject" fullword
		$gen2 = "myRObject" fullword
		$gen3 = { 6A (02|03) 6A 00 6A 00 68 00 00 00 C0 50 FF 15 } // CreateFileA args
	condition:
		2 of them
}
