# Cyber-Sec-Notes

Just a small note takin page that keep adding to it. For shits and giggles later:

# OSCP and Offensive Pathway

If new to Kali Environment go to first step to setup the environment and move from there.

- [Environment Setup](/setup/README.md)

Second is to look at **My Linux Playground** and find out if you know all the good stuff about linux. I refer to it from time to time to refresh my mind on some commands I keep forgetting.

- [Linux Playground](/offensive/linux-playground.md)

Then, if you are ready, you can go to the following locations to find what you are looking for:

- [Generic High level Enumeration](/offensive/enumeration.md)
- [Linux Enumeration](/offensive/enumeration-linux.md)
- [Windows Enumeration](/offensive/enumeration-windows.md)
- [Web Application Enumeration]

There are some [high level usual stuff](/offensive/README.md) that I use on the main page of Offensive path as well.

# Blue Teaming and Defensive Pathway

Coming Soon....

# Reverse Engineering:

For reverse engineering I haven't added a lot of stuff yet. I'm just going through couple of courses and learning here and there from whatever I can.

- [Setting up the environment](/Reverse%20Engineering/README.md)

# Random Notes

## Deleting Image Files that are removed from Markdown (Windows)

Sometimes, you copy paste stuff in your note taking app, but then delete images from it in Markdown. The image files don't usually get deleted because only reference to them is delete. Below is a walkthrough of how Powershell command is created to delete them:

`Get-ChildItem .\_resources\ | Where { (Get-ChildItem -Path 'C:\Users\Kev\kevNotes\*.md' -Recurse | Select-String $_.Name).Count -eq 0 } | ForEach { $_.FullName } | Remove-Item`

## Setting up Atom Markdown Editor
You can refer to couple of packages for atom.io to write markdown as well. Sometimes good replacement for Obsidian.
-[Markdown Writer](https://github.com/zhuochun/md-writer/wiki/Settings-for-Keymaps)
  -[You can have your custom key bindings as well](https://github.com/zhuochun/md-writer/wiki/Settings-for-Keymaps)
-[linter-Markdown](https://github.com/AtomLinter/linter-markdown)
-[markdown-image-assistant](https://github.com/tlnagy/atom-markdown-image-assistant)
