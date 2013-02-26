#Parsing Windows Jump Lists:


PREFACE:
When writing a parser for windows jump list files, a few things are essential to understand. First, you must know the file structure implemented within a windows jump list. Second, you must be able to recognize a jump list file, and know where to access these files. Third, you must understand how to parse a file with a hexadecimal editor.


##1) Define CFB Structure Utilized In Jump Lists:

A variable for each aspect of the CFB file structure (as seen in /doc/references/ms_cfb.pdf) has been written in /src/ms_cfb/cfb.py. The code will be used to store bit information parsed from the Jump List files.




##2) Locating Jump List Files:

1. Jump List file names are constructed in this fassion: Sixteen hexidecimal characters followed by a period, followed by destination name (automaticDestinations or customDestinations) followed by a hyphen, and condluded with the characters "ms".

examples:  	28c8b86deab549a1.automaticDestinations-ms 
		14bdd67f29cb1962.customDestinations-ms


2. Windows 7 Jump List files are located in two directories: 

C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\

and

C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\


3. As you may have guessed, files ending in "automaticDestinations-ms" go to the AutomaticDestinations folder, while files ending in "customDestinations-ms" are allocated to the CustomDestinations folder.



##3) Parsing Jump List Files:


