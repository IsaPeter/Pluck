from pluck.core import PayloadInjector
from httplib import HTTPRequest, HTTPResponse 
import pluck.settings as settings
import random, string
import urllib.parse



class BaseModule:
    def __init__(self, request):
        # The original request which we working for
        self.original_request = request

        # Name of the module
        self.name = ""

        # Print debug messages
        self.debug = False
   
    def run(self, injector, sender):
        """Payload injektálása és küldése."""
        raise NotImplementedError("Implementáld a futtatást")

    def analyze_response(self, response):
        """Válasz elemzése sérülékenység szempontjából."""
        raise NotImplementedError("Implementáld az elemzést az alosztályban.")
    
    


class ActiveModule(BaseModule):
    def __init__(self, request):
        super().__init__(request)

         # the sleep timeout value for the payload generators
        self.sleep_timeout = 15

        # The domain name or pt address for testing and generating payloads
        self.domain = "127.0.01"

        # Unique string for testing purposes
        self.unique_string = self.generate_unique_string()

        # Parameter list ot be test
        self.test_parameters = []

        # injection points list where the injector inject payloads
        self.injection_points = []

        # parameters excluded from the payload injection
        self.excluded_parameters = []

        # The payload generator instance
        self.generator = None

        # Continue testing after successfully detect a vulnerability
        self.continue_on_success = False

        # The sender module which send the actual requests
        self.request_sender = None

        self.module_type = 'active'

        # String which may appear in the response means a possible vulnerability!
        self.evidence_strings = []

        self.stop_testing = False

    # Allpy the settings from global settings
    def apply_settings(self):
        if settings:
            # Set the global timeout settings
            self.sleep_timeout = settings.sleep_timeout

            # Set the domain address for payload generation
            self.domain = settings.collaborator_domain

            # Set the parameter list for testing
            self.test_parameters = settings.testing_parameters

            # Set the excluded parameters list
            self.excluded_parameters = settings.exclude_parameters

            # Set the injection points
            self.injection_points = settings.injection_points

            # Set the continuation on success
            self.continue_on_success = settings.continue_on_success

            # load the request sender from the settings
            self.request_sender = settings.request_sender

    # Generete unique string for testing purposes 
    def generate_unique_string(self, length=16):
            return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(length))

    # Generate the requests for the sender
    def generate_requests(self, payloads):
        # Create an injector
        injector = PayloadInjector(HTTPRequest(self.original_request.rebuild_request()))
        
        # Injection dictionary létrehozása
        injection_dict = injector.find_injection_points() # This stores an injection dictionary

        # Get the available injection points where possible to inject 
        # eg.: has a parameter
        if self.injection_points:
            available_inj = [k for k in injection_dict.keys() if injection_dict[k] and k in self.injection_points]
        else:
            available_inj = [k for k in injection_dict.keys() if injection_dict[k]]    
        
        # Collect all the points and parameters
        if not self.test_parameters:
            inj_parameters = [(point,param) for point in available_inj for param in injection_dict[point] if param not in self.excluded_parameters]
        else:
            inj_parameters = [(point,param) for point in available_inj for param in injection_dict[point] if param in self.test_parameters]
        
        # A list which will contain a generated requests
        request_list = []

        # iterate through all the points, parameters and payloads and generate available requests
        for point,param in inj_parameters:
            for payload in payloads:
                new_request = HTTPRequest(self.original_request.rebuild_request())
                injector = PayloadInjector(new_request)
                injector.inject_payload(point, param, payload)
                request_list.append((payload, point, param, new_request))

                appended = HTTPRequest(self.original_request.rebuild_request())
                injector_ap = PayloadInjector(appended)
                injector_ap.inject_payload(point, param, payload, append=True)
               
                request_list.append((payload, point, param, appended))


        return request_list
    
    def _get_injection_points(ip,ep,tp,inj):
        available_inj = [k for k in inj.keys() if inj[k]]    
        available_ip = [p for p in ip if p in available_inj ]
        
        if not tp:
            inj_parameters = [(point,param) for point in available_inj for param in inj[point] if param not in ep]
        else:
            inj_parameters = [(point,param) for point in available_inj for param in inj[point] if param in tp]

        return inj_parameters

    # Function to use for payload generation
    def generate_payloads(self):
        if self.generator:
            # set the necessary informations
            self.generator.sleep_timeout = self.sleep_timeout
            self.generator.domain = self.domain
            self.generator.unique_string = self.unique_string
            
            # Generating and return the requests
            payloads =  self.generator.generate_payloads()

            # obtain evicende strings from generator if available
            self.evidence_strings = self.generator.evidence_strings

            # Execute the extending function
            extended = self.extend_payloads()
            if extended:
                payloads.extend(extended)

            return payloads
        else:
            return []

    # Sending the generated requests with the request sender module
    def send_requests(self, request_list):
        for payload, point, param, req in request_list:
            if not self.stop_testing:
                response = self.request_sender.send_request(req)
                self.analyze_response(response, req, payload, point, param)
            else:
                break
            
    # This function extending the payload generation without required to modigy the generate_payload function()
    def extend_payloads(self):
        return []

    # Run the actual module
    def run(self):
        # Execute things before everything
        self.execute_before()

        # Generate payloads with local function
        print(f"[*] Executing the {self.name} module")
        payloads = self.generate_payloads()

        # generate the requests from payloads
        generated_requests = self.generate_requests(payloads)

        # send all the requests
        self.send_requests(generated_requests)

        # execute things after run
        self.execute_after()

    def stop_test(self):
        self.stop_testing = True

    # Analyze the response, but not implemented here, implement it in the higher level class
    def analyze_response(self, response, request, payload, point, param):
        pass

    # possibility to execute code before run method
    def execute_before(self):
        pass
    
    # possibility to execute code after run method
    def execute_after(self):
        pass


class PassiveModule():
    def __init__(self, response):
        self.response = response
        
        # Name of the module
        self.name = "Passive Module"

        self.module_type = 'passive'

    # Run the module
    def run(self):
        if self.response:
            self.analyze_response()

    # Analyze the response of the module
    def analyze_response(self):
        pass


# Module for payload generation
class GenerationModule():
    def __init__(self):
        # Default value of sleep timeout
        self.sleep_timeout = 15
        # Default value of unique string
        self.unique_string = ""
        # default value of domain
        self.domain = "127.0.0.1"

        # contains the possible injection evidences
        self.evidence_strings = []

    # payload generation process
    def generate_payloads(self):
        return []
    
    # replace the static string in the templates
    def change_variables(self,template, additional=[]):
        result = template.replace("UNIQUE",self.unique_string)
        result = result.replace("TIMEOUT",str(self.sleep_timeout))
        result = result.replace("DOMAIN",str(self.domain))


        try:
            if additional:
                for f,t in additional:
                    result = result.replace(f,str(t))
        except Exception as e:
            #print(e)
            pass
        
        return result

    # Url encode a list of strings
    def url_encode(self, lista):
        return [urllib.parse.quote(p) for p in lista]
    
    # Append evidence to the list
    def append_evidence(self, evidence):
        self.evidence_strings.append(evidence)

    # get the generated evidences from the class
    def get_evicendes(self):
        return self.evidence_strings