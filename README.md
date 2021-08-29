# Cyber-Sec-Notes

Just a small note takin page that keep adding to it. For shits and giggles later:

## The Begining Pathway

If new to Kali Environment go to first step to setup the environment and move from there.

- [Environment Setup](/setup/README.md)

Second is to look at **My Linux Playground** and find out if you know all the good stuff about linux. I refer to it from time to time to refresh my mind on some commands I keep forgetting.

- [Linux Playground](/offensive/linux-playground.md)

## Offensive

There are some [high level usual stuff](/offensive/README.md) that I use on the main page of Offensive. Then, if you are ready for offense, you can go to the following locations to find what you are looking for:

- [Initial Access or Foothold](/offensive/initial_access.md)
- [Linux Enumeration](/offensive/enumeration-linux.md)
- [Windows Enumeration](/offensive/enumeration-windows.md)
- [Web Application Enumeration](/offensive/enumeration-webApp.md)
- [SQLMAP](/offensive/SQLMap.md)

## Defensive

Coming Soon....

## Industrial Control Material

This folder is dedicated to the tools and codes and methods I usually use for ICS and things that are solely related to ICS stuff. Have a that in mind sometimes it leverages off the back of existing Offensive TTPs that mentioned within **Offensive** folder.

- [Industrial Controls System](/ICS/README.md)

## Topics of Interest

### Exploit Development

If you have come across something and you would like to develop an exploit for it, or fuzz it to see if something comes out of it maybe give this page a try. It might have some useful stuff in there.

- [Generic Exploit Development](/ExploitDevelopment/README.md)

### Reverse Engineering

For reverse engineering I haven't added a lot of stuff yet. I'm just going through couple of courses and learning here and there from whatever I can.

- [Setting up the environment](/Reverse%20Engineering/README.md)

## Tools and Cheat Sheets Use Often

- [Python Code Blocks Used for Quick Commands](/random_tools/python_codeblocks.md)
- [Hashcat Cheat Sheet](/random_tools/hashcat_cheatsheet.md)
- [Tshark cheat Sheet commands](/random_tools/tshark.md)
- [Meterpreter Interaction Help and Usefull Explaination](/random_tools/Meterpreter.md)
- [Working with Regular Expression](/random_tools/Regular%20Expression.md)
- [Spawn a Shell](/random_tools/Spawn_a_shell.md)
- [MSFvenom One liners any one?](/random_tools/MSFvenom%20Oneliners.md)
- [Some generic Methology of pen testing with links](/random_tools/Methodology-Generic.md)

## Random Notes

### Deleting Image Files that are removed from Markdown (Windows)

Sometimes, you copy paste stuff in your note taking app, but then delete images from it in Markdown. The image files don't usually get deleted because only reference to them is delete. Below is a walkthrough of how Powershell command is created to delete them:

`Get-ChildItem .\_resources\ | Where { (Get-ChildItem -Path 'C:\Users\Kev\kevNotes\*.md' -Recurse | Select-String $_.Name).Count -eq 0 } | ForEach { $_.FullName } | Remove-Item`

### Setting up Atom Markdown Editor

You can refer to couple of packages for atom.io to write markdown as well. Sometimes good replacement for Obsidian.
-[Markdown Writer](https://github.com/zhuochun/md-writer/wiki/Settings-for-Keymaps)
  -[You can have your custom key bindings as well](https://github.com/zhuochun/md-writer/wiki/Settings-for-Keymaps)
-[linter-Markdown](https://github.com/AtomLinter/linter-markdown)
-[markdown-image-assistant](https://github.com/tlnagy/atom-markdown-image-assistant)
