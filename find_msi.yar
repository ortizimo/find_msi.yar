
rule find_msi
{					
	meta:
		author = "Saulo 'Sal' Ortiz, Sr. Cyber Forensics Analyst, ATG"
		description = "Simple rule to find .MSI files"
		date = "2021-10-22"
		updated = "2022-03-07"
		
		note1 = "Files in $Recycle.Bin do not show their actual name. Look for the file's metadata file ($I...) for its actual name"
		note2 = "MSI shares HEX with other files. Filter findings using Notepad++"		
		
	strings:
		$magic = { d0 cf 11 e0 a1 } private	
		$MSI = /[a-zA-Z0-9\.,!@#$%^&\*\(\)_+{\[}\?:><|\\]{1,30}\.msi/ nocase fullword ascii private 
				
		$n01 = /\%s.txt/ nocase
		$n02 = /\%s.doc/ nocase		
		$n03 = /\%s.jrs/ nocase
		$n04 = /\%s.html/ nocase
		$n05 = /\%s.cmtx/ nocase
		$n06 = /\%s.dat/ nocase
		$n07 = /\%s.tmp/ nocase
		$n08 = /\%s.svg/ nocase
		$n09 = /\%s.xsl/ nocase
		$n10 = /\%s.log/ nocase
		$n11 = /\%s.ppt/ nocase
		$n12 = /\%s.mdb/ nocase
		$n13 = /\%s.pdf/ nocase
		$n14 = /\%*.msp/ nocase
		$n15 = /\%s.yar/ nocase		// tries to blocks this rule from scanning itself if scanning from the same folder as running rule
		
	condition:
		($magic at 0 and $MSI) and not any of ($n*)
}
