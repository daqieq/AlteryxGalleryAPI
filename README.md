 # AlteryxGalleryAPI - CLI version

AlteryxGalleryAPI is a python CLI used for connecting to the Alteryx Gallery. For non-CLI version, look at the original repository (Theamazingdp): https://github.com/Theamazingdp/AlteryxGalleryAPI

It includes a class that can request Gallery information, send workflow execution commands, monitor
job status, and retrieve the desired workflow output.

The official Alteryx API documentation can be found at: https://gallery.alteryx.com/api-docs/

 ## Setup and Install
In order to access the Gallery you must obtain an API key, secret and you must have the URL to your Alteryx Gallery.

Note: This library is not avaliable through via PyPI and must be installed locally and placed in your working directory.

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
