import pluck.settings as settings
from pluck.generators.traversal import DirectoryTraversalPayloadGenerator
from pluck.module import ActiveModule




class DirectoryTraversalTester(ActiveModule):
    def __init__(self, request):
        super().__init__(request)
        self.name = "Directory Traversal Tester"
        self.test_parameters = []
        self.injection_points = ["path","query", "body", "headers", "cookies"]
        self.excluded_parameters = []
        self.generator = DirectoryTraversalPayloadGenerator()

        self.success_strings = [
            'This is a sample HOSTS file used by Microsoft',
            'Copyright (c) 1993-2009 Microsoft Corp.',
            'root:x:0:0:root:/root',
        ]

        self.linux_success_files = ['resolv.conf', 'passwd', 'shadow']
        self.windows_success_files = ['ntdll.dll','ntdsapi.dll','winlogon.exe']


   
    def analyze_response(self, response, request, payload, point, param):
        issue_found = False
        
        # check root in passwd
        for message in self.success_strings:
            if message.lower() in response.body.lower():
                settings.finding_library.add_finding(name="Directory Traversal",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
                issue_found = True

        if all([s.lower() in response.body.lower() for s in self.linux_success_files ]):
            settings.finding_library.add_finding(name="Directory Traversal",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True
        
        if all([s.lower() in response.body.lower() for s in self.windows_success_files ]):
            settings.finding_library.add_finding(name="Directory Traversal",payload=payload, point=point, param=param, module=self.name, request=request, response=response)
            issue_found = True
        
        
        if issue_found and not self.continue_on_success:
            self.stop_test()  



