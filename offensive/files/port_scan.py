from autorecon import PortScan, Service

class QuickTCP(PortSCan)

    def __init__(self):
        super().__init__()  #this is how you do subclassing in python
        self.name = 'Quick TCP Scan' #declaring its function name

    async def run(self, target):
        #the execute returns 3 parameters.
        process, stdout, stderr = await target.execute('nmap {nmap_extra} -sV -sC --version-all -oN "{scandir}/_quick_tcp_nmap.txt" -oX "{scandir}/xml/_quick_tcp_nmap.xml" {address}')
        services = await target.extract_services(stdout)

        return services
