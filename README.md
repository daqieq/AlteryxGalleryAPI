 # AlteryxGalleryAPI - CLI version

AlteryxGalleryAPI is a python CLI used for connecting to the Alteryx Gallery. For non-CLI version, look at the original repository (Theamazingdp): https://github.com/Theamazingdp/AlteryxGalleryAPI

It includes a class that can request Gallery information, send workflow execution commands, monitor
job status, and retrieve the desired workflow output.

The official Alteryx API documentation can be found at: https://gallery.alteryx.com/api-docs/

 ## Setup and Install
In order to access the Gallery you must obtain an API key, secret and you must have the URL to your Alteryx Gallery.

Pick a directory on your server/client where you want to run the application. It is recommended generally to create a virtual environment for testing, and even most production uses. In my case, I didn't want the main python installation that would be used for other uses to be impacted by, or impact, my AlteryxGalleryAPI application. So I created a venv for it to use exclusively:

```
python -m venv AlteryxAPI_venv
```

 ## Usage
The CLI is run from the command line and here is the help information as currently configured:
```
(venv) C:\Users\username\more\dirs>python ayx-cli.py -h
usage: ayx-cli.py [-h] (-s S | -t T) [-a A] [-v] server key secret

Python Command Line Interface for sending requests to the Alteryx Server

positional arguments:
  server             gallery server name e.g. yourserveraddr
  key                gallery subscription key
  secret             gallery subscription secret

optional arguments:
  -h, --help         show this help message and exit
  -s S, --submit S   search for an App and submit it
  -t T, --status T   get status of running App using a Job Id
  -a A, --answers A  list of answers to app questions, implies -s
  -v, --verbose      log more information to the output, default is false
```
