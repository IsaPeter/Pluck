from argparse import ArgumentParser
from httplib import HTTPRequest, HTTPResponse, HTTPRequestSender
from pluck.core import PayloadInjector, FindingLibrary
import pluck.settings as settings
import os, sys
import issuelib as issuelib

#from pluck.modules.test_module import TestModule
from pluck.modules.xss_test_module import XssTester
from pluck.modules.http_methods import HttpMethodTester2
from pluck.modules.html_injector import HTMLInjectionTester3
from pluck.modules.command_injector import OSCommandInjector
from pluck.modules.open_redirector import OpenRedirectionInjector
from pluck.modules.reflection_tester import ParameterReflectionTester
from pluck.modules.php_injection import PHPCodeInjectionTester
from pluck.modules.ssi_injection import SSIInjectionTester
from pluck.modules.sql_injection import SQLInjectionTester
from pluck.modules.directory_traversal import DirectoryTraversalTester
from pluck.modules.template_injection import TemplateInjectionTester
from pluck.modules.crlf_injector import CRLFInjectionTester
from pluck.modules.shellshock import ShellShockTester


# Load the request from file.
def load_request(path):
    if os.path.isfile(path):
        with open(path, 'r') as f:
            data = f.read()
        return data

def print_test_parameters(request):
    print("### Testing Parameters ###")
    print("URL: ", request.get_request_url())
    print("PATH: ", request.path )
    print("METHOD: ", request.method)
    if settings.proxy: print("Proxy:" , settings.proxy["http"])
    if settings.base_address: print("Base Address: ",settings.base_address)
    if settings.port_number: print("PORT: ", settings.port_number)
    if settings.protocol: print("PROTOCOL: ", settings.protocol) 
    if settings.ignore_certificate: print("Ignore CERT: ", "True")



# Parsing the arguments
def parse_arguments():
    parser = ArgumentParser(description="Pluck Web Tester")
    parser.add_argument("-r","--request", dest="request", help="Set the initial request")
    parser.add_argument("-x","--proxy", dest="proxy", help="Set the Proxy")
    parser.add_argument("-b","--base-address", dest="base_address", help="Set the base address for URL creation")
    parser.add_argument("-s","--protocol", dest="protocol", help="Set the protocol http/https")
    parser.add_argument("-p","--port", dest="port", help="Set the web application port number")
    parser.add_argument("-k","--ignore-certificate", dest="ignire_cert", action="store_true", help="Ignore the SSL Warnings")
    parser.add_argument("-I","--injection-points", dest="injection_points", help="Set injection points ',' coma separated")
    parser.add_argument("--payload-timeout", dest="payload_timeout", help="Set the payload timeout.")
    parser.add_argument("-m","--modules", dest="modules", help="Set the using modules")
    parser.add_argument("-P","--parameters", dest="parameters", help="Set the testing parameters")
    parser.add_argument("--oast", dest="oast", help="Set Collaborator address for OAST")
    parser.add_argument("--exclude-parameter", dest="exclude_parameter", help="Exclude parameter from testing")
    parser.add_argument("--continue-on-success", dest="continue_on_success", action="store_true", help="Continue Testing if found a vulnerability")
    parser.add_argument("--list-modules", dest="list_modules", action="store_true", help="List the available modules")
    parser.add_argument("--test",dest="testing",action="store_true")
    


    return parser.parse_args()

def testing(parsed_request):
  
    tester = XssTester3(parsed_request)
    print("Applying settings")
    tester.apply_settings()
    tester.run()

def main():
    # Parsing the inline arguments
    args = parse_arguments()


    if args.request:
        raw_request = load_request(args.request)

    if args.proxy:
        settings.proxy = {"http":args.proxy,"https":args.proxy}
    
    if args.base_address:
        settings.base_address = args.base_address

    if args.protocol:
        settings.protocol = args.protocol
    
    if args.port:
        settings.port_number = int(args.port)

    if args.ignire_cert:
        settings.ignore_certificate = True

    if args.injection_points:
        if "," in args.injection_points:
            settings.injection_points = [p.strip() for p in args.injection_points.split(",")]
        else:
            settings.injection_points.append(args.injection_points.strip())
    else:
        settings.injection_points = ["path", "query", "body", "headers", "cookies"]

    modules = []
    if args.modules:
        modules = [m.lower().strip() for m in args.modules.split(',')]

    if args.parameters:
        settings.testing_parameters = [param.strip() for param in args.parameters.split(',')]

    if args.oast:
        settings.collaborator_domain = args.oast

    if args.exclude_parameter:
        if ',' in args.exclude_parameter:
            settings.exclude_parameters = [p.strip() for p in args.exclude_parameter.split(',')]
        else:
            settings.exclude_parameters = args.exclude_parameter.strip() 

    if args.continue_on_success:
        settings.continue_on_success = True
    
    if args.payload_timeout:
        settings.sleep_timeout = args.payload_timeout





    sender = HTTPRequestSender()
    if settings.proxy: sender.proxies = settings.proxy
    if settings.base_address: sender.address = settings.base_address
    if settings.port_number: sender.port_number = settings.port_number
    if settings.protocol: sender.protocol = settings.protocol
    if settings.ignore_certificate: sender.verify = False

    settings.request_sender = sender

    # Create the Finding Library and place into the settings 
    # to able to access globally
    library = FindingLibrary()
    settings.finding_library = library



    # parse the initial request
    parsed_request = HTTPRequest(raw_request)
    print_test_parameters(parsed_request)

    # Application available modules
    available_modules = {
        "xss":XssTester(parsed_request),  # OK
        "http_methods" : HttpMethodTester2(parsed_request), # OK
        "html_injection" : HTMLInjectionTester3(parsed_request), # OK
        "command_inject" : OSCommandInjector(parsed_request), # OK
        "ored" : OpenRedirectionInjector(parsed_request), # OK
        #"test": TestModule(parsed_request),
        "reflection" : ParameterReflectionTester(parsed_request), # OK
        "php": PHPCodeInjectionTester(parsed_request), # OK
        "ssi" : SSIInjectionTester(parsed_request), # OK
        "sqli" : SQLInjectionTester(parsed_request), # OK
        "traversal" : DirectoryTraversalTester(parsed_request), #OK
        "template" : TemplateInjectionTester(parsed_request), # OK
        "crlf" : CRLFInjectionTester(parsed_request), 
        "shellshock": ShellShockTester(parsed_request), 
    }

    if args.list_modules:
        print("Reference\t\tName\n"+"#"*30)
        for name, module in available_modules.items():
            print(f"{name}\t\t{module.name}")
        sys.exit(0)

    if args.testing:
        testing(parsed_request)
        sys.exit(0)
        




    print("Parameters To Test: ", settings.testing_parameters)
    print("Modules to run: ", modules)
    print("Injection POints: ", settings.injection_points)
    

    if modules:
        for module in modules:
            if module in available_modules:
                m = available_modules[module]
                m.sender = sender # ez majd nem kell ha az összes modul át lesz írva
                m.request_sender = sender
                m.test_parameters = settings.testing_parameters
                m.injection_points = settings.injection_points
                m.excluded_parameters = settings.exclude_parameters
                #m.apply_settings()
                m.run()
    else:
        for module in available_modules:
            m = available_modules[module]
            m.sender = sender
            m.request_sender = sender
            m.test_parameters = settings.testing_parameters
            m.injection_points = settings.injection_points
            m.excluded_parameters = settings.exclude_parameters
            m.apply_settings()
            m.run()


   


    print("Library Items: ", len(library.findings))
    for f in library.findings:
        print(f"[!] {f.name} found in {f.injection_point} {f.parameter} parameter with {f.payload} payload! Request ID: {f.request_id}")


    



if __name__ == '__main__':
    main()