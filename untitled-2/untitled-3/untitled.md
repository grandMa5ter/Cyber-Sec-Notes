# 0. Installing Docker & Juice Shop

 1. Run the below commands in exact sequence.

 root@kali:~/Desktop\# curl -fsSL [https://download.docker.com/linux/debian/gpg](https://download.docker.com/linux/debian/gpg) \| apt-key add -  
root@kali:~/Desktop\# echo 'deb \[arch=amd64\] [https://download.docker.com/linux/debian](https://download.docker.com/linux/debian) buster stable' &gt; /etc/apt/sources.list.d/docker.list  
root@kali:~/Desktop\# apt update  
root@kali:~/Desktop\# apt install docker-ce  
root@kali:~/Desktop\# docker pull bkimminich/juice-shop

 2. Run the Juice Shop over Docker  
root@kali:~/Desktop\# docker run --rm -p 3000:3000 bkimminich/juice-shop

 GO through the below Gitbook of solutions of Juice Shop  
[https://bkimminich.gitbooks.io/pwning-owasp-juice-shop/content/appendix/solutions.html](https://bkimminich.gitbooks.io/pwning-owasp-juice-shop/content/appendix/solutions.html)

