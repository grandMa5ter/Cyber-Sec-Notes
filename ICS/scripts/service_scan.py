from autorecon import ServiceScan
import os

class dirsearch(ServiceScan):

    def __init__(self):
		super().__init__()
		self.name = "DirSeach"
        #self.priority = 0
		self.tags = ['Custom', 'dirSearch']

    def configure(self):
		self.match_service_name('^http')
		self.match_service_name('^nacn_http$', negative_match=True)
        self.add_option('threads', default=10, help='The number of threads to use when directory busting. Default: %(default)s')
        self.add_choice_option('tool', defaults='feroxbuster', choice=['feroxbuster', 'gobuster', 'dirsearch'], help='The tool you want to use. Default: %(default)s')
        self.add_list_option('wordlist', default=['/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt'], help='The wordlist to use when directory busting. Specify the option multiple times to use multiple wordlists. Default: %(default)s')

    async def run(self, service):
        for wordlist in self.get_option('wordlist'):
            name = os.path.splitext(os.path.basename(wordlist))[0]
            if self.get_option('tool') == 'dirsearch':
                await service.execute('sudo python3 /opt/dirsearch/dirsearch.py -u {http_scheme}://{address}:{port}/' + str(self.get_option('threads')) + '-e php,html,jsp,aspx,js -x 400,401,403 -w ' + wordlist)

    def manual(self):
		self.add_manual_command('Here is a shorter version of dirsearch', [
			'sudo python3 /opt/dirsearch/dirsearch.py -u {http_scheme}://{address}:{port}/ ' + str(self.get_option('threads')) + '-e php,html,jsp,aspx,js -x 400,401,403' + wordlist
		])
