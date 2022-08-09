# Cyber-Sec-Notes

Just a small note takin page that keep adding to it. For shits and giggles later:

## The Begining Pathway

If new to Kali Environment go to first step to setup the environment and move from there.

- [Environment Setup](/Setup/README.md)

Second is to look at **My Linux Playground** and find out if you know all the good stuff about linux. I refer to it from time to time to refresh my mind on some commands I keep forgetting.

- [Linux Playground](/Offensive/linux-playground.md)

## Offensive

There are some [high level usual stuff](/Offensive/README.md) that I use on the main page of Offensive. Then, if you are ready for offense, you can go to the following locations to find what you are looking for:

- [Initial Access or Foothold](/Offensive/initial_access.md)
- [Linux and Windows Full Exploit Paths](/Offensive/attack_notes.md)
- [Web Application Enumeration](/Offensive/attack_notes.md/#http-enumeration--always-search-for-txtphpaspaspx-files)
- [SQLMAP](/Offensive/SQLMap.md)

## Defensive

Coming Soon....

## Topics of Interest

### Exploit Development & Reverese Engineering

If you have come across something and you would like to develop an exploit for it, or fuzz it to see if something comes out of it maybe give this page a try. It might have some useful stuff in there. For reverse engineering I haven't added a lot of stuff yet. I'm just going through couple of courses and learning here and there from whatever I can.

- [Generic Exploit Development](/ExploitDevelopment/README.md)

### Industrial Control Material

This folder is dedicated to the tools and codes and methods I usually use for ICS and things that are solely related to ICS stuff. Have a that in mind sometimes it leverages off the back of existing Offensive TTPs that mentioned within **Offensive** folder.

- [Industrial Controls System](/ICS/README.md)

## Tools and Cheat Sheets Use Often

- [Python Code Blocks Used for Quick Commands](/Random_tools/python_codeblocks.md)
- [Hashcat Cheat Sheet](/Random_tools/hashcat_cheatsheet.md)
- [Tshark cheat Sheet commands](/Random_tools/tshark.md)
- [Meterpreter Interaction Help and Usefull Explaination](/Random_tools/Meterpreter.md)
- [Working with Regular Expression](/Random_tools/Regular%20Expression.md)
- [Spawn a Shell](/Random_tools/shells.md)
- [MSFvenom One liners any one?](/Random_tools/MSFvenom%20Oneliners.md)
- [Some generic Methology of pen testing with links](/Random_tools/Methodology-Generic.md)

## Random Notes

### Deleting Image Files that are removed from Markdown (Windows)

Sometimes, you copy paste stuff in your note taking app, but then delete images from it in Markdown. The image files don't usually get deleted because only reference to them is delete. Below is a walkthrough of how Powershell command is created to delete them:

`Get-ChildItem .\_resources\ | Where { (Get-ChildItem -Path 'C:\Users\Kev\kevNotes\*.md' -Recurse | Select-String $_.Name).Count -eq 0 } | ForEach { $_.FullName } | Remove-Item`
