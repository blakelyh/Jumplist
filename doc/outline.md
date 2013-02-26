#Parsing Windows Jump Lists:
###1) Define CFB structure utilized in Jump Lists.
###2) Locate all Jump List files.
###3) Parse all Jump List files using defined CFB structures.

## 


###CFB Structure Utilized In Jump Lists:

A variable for each aspect of the CFB file structure has been written in /src/ms_cfb/cfb.py. The code will be used to store bit information parsed from the Jump List files.




###Locating Jump List Files:

1. Jump List file names are constructed in this fassion: Sixteen hexidecimal characters followed by a period, followed by destination name (automaticDestinations or customDestinations) followed by a hyphen, and condluded with the characters "ms".

examples:  	28c8b86deab549a1.automaticDestinations-ms 
		14bdd67f29cb1962.customDestinations-ms

2. Windows 7 Jump List files are located in two directories 





###Parsing Jump List Files:


