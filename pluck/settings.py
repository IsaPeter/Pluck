# Set the proxy for the Request Sender
proxy = {"http":"127.0.0.1:8080","https":"127.0.0.1:8080"}

# Defining the injection points
injection_points = [] # all / path / query / body / headers / cookies

# Define the base address of the insertion
base_address = None

# Set the port number of the attack target
port_number = 0

# Set the protocol for the requests
protocol = None

# Ignore the certificate
ignore_certificate = None

testing_parameters = []

collaborator_domain = "127.0.0.1"

exclude_parameters = []

continue_on_success = False

# Timeout for generating time based payloads
sleep_timeout = 15

request_sender = None

finding_library = None