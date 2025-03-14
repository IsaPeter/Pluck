from argparse import ArgumentParser
from httplib import HTTPRequest, HTTPResponse, HTTPRequestSender
from pluck.core import PayloadInjector, FindingLibrary
import pluck.settings as settings
import os, sys
from terminaltables3 import AsciiTable
from textwrap import wrap


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
    parser = ArgumentParser(description="Pluck Web Application Vulnerability Tester")

    rh_parser = parser.add_argument_group("Pluck Request Handling")
    rh_parser.add_argument("-r","--request", dest="request", metavar="", help="Set the initial request")
    rh_parser.add_argument("-x","--proxy", dest="proxy", metavar="", help="Set the Proxy")
    rh_parser.add_argument("-b","--base-address", dest="base_address", metavar="", help="Set the base address for URL creation")
    rh_parser.add_argument("-s","--protocol", dest="protocol", metavar="", help="Set the protocol http/https")
    rh_parser.add_argument("-p","--port", dest="port", metavar="", help="Set the web application port number")
    rh_parser.add_argument("-k","--ignore-cert", dest="ignore_cert", action="store_true", help="Ignore the SSL Warnings")
    
    
    general_parser = parser.add_argument_group("Pluck General Options")
    general_parser.add_argument("--list-modules", dest="list_modules", action="store_true", help="List the available modules")
    general_parser.add_argument("-li","--list-injection-points", dest="list_injection_points", action="store_true", help="List the available injection points")
    general_parser.add_argument("--test",dest="testing",action="store_true")
    
    exec_parser = parser.add_argument_group("Pluck Execution Options")
    exec_parser.add_argument("-I","--injection-points", dest="injection_points", metavar="", help="Set injection points ',' coma separated")
    exec_parser.add_argument("--payload-timeout", dest="payload_timeout", metavar="", help="Set the payload timeout.")
    exec_parser.add_argument("-m","--modules", dest="modules", metavar="", help="Set the using modules")
    exec_parser.add_argument("-P","--parameters", dest="parameters", metavar="", help="Set the testing parameters")
    exec_parser.add_argument("--oast", dest="oast", metavar="", help="Set Collaborator address for OAST")
    exec_parser.add_argument("--exclude-parameter", dest="exclude_parameter", metavar="", help="Exclude parameter from testing")
    exec_parser.add_argument("--continue-on-success", dest="continue_on_success", action="store_true", help="Continue Testing if found a vulnerability")
    


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

    if args.ignore_cert:
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
        table_data = [["Module Name","Summary"]]
        for name, module in available_modules.items():
            table_data.append([name, module.name])
        print(AsciiTable(table_data).table)
        sys.exit(0)

    if args.list_injection_points:
        if parsed_request:
            table_data = [["Injection Points", "Parameters"]]
            table = AsciiTable(table_data)
            inj = PayloadInjector(parsed_request)
            ip = inj.find_injection_points()
            for point in ip.keys():
                longstr = ', '.join([i for i in ip[point]])
                max_width = table.column_max_width(1)
                wrapped_string = "\n".join(wrap(longstr, max_width))
                table.table_data.append([point.title(), wrapped_string])
            print(table.table)
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