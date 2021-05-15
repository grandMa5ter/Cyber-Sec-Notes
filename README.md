# Cyber-Sec-Notes

Just a small note takin page that keep adding to it. For shits and giggles later:

PowerShell-based penetration testing tools:
- Empire
- Apfell
- Covenant
- Silver
- Faction

- How to use remote desktop from Kali:
rdesktop $IP -g 95%

- How to install python 2 on Kali 2020.x onwards:

download the bloody get-pip.py from here:

curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
pip2 --version
pip install --upgrade setuptools
sudo pip install --upgrade setuptools
sudo pip2 install #[py 2 package]


#Setting up the terminator for Kali 2020.x onwards:

sudo apt install terminator

Or if they don't have the repo:
sudo add-apt-repository ppa:gnome-terminator
sudo apt-get update
sudo apt-get install terminator

Setup:
- In preferences:
Infinite scrollback is selected
Profiles>colors>Change palette to "White on Black"
Profiles>Background>Solid Color

- Google Search Plugin:
https://github.com/msudgh/terminator-search

- Shortcuts
Ctrl + Shift + O = Virtual Split
Ctrl + Shift + E = Horizontal Split
Ctrl + Shift + Z = Maximizes a current tabbed window to full screen and then restores to tabbed by pressing again

- installing power line fonts:
> sudo apt install fonts-powerline
>

- highlighting the syntax is found below:
https://github.com/zsh-users/zsh-syntax-highlighting
