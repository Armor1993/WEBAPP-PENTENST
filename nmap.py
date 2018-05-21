from libnmap.process import NmapProcess
from time import sleep
from libnmap.parser import NmapParser, NmapParserException
from xmljson import cobra as cb
from xml.etree.ElementTree import fromstring
import json
from environment import *


# TODO operating system of the scanned machine


class Nmap:
    """
    Runs the Nmap test and parses output, returning a dictinary of finding to the databse
    """

    @staticmethod
    def create_nmprocess(scan_id):
        """
        Creates a Process object for the scan id provided; and adds it to the database
        :param scan_id: Id of the scan object that is related to the process
        :return: None
        """
        # query the database to get the domain out of the connected scan and target tables
        target_scan = Scan.query.filter_by(id=scan_id).first()
        target_domain = Target.query.filter_by(id=target_scan.target_id).first().domain
        # Create new process object
        proc = Process()
        proc.scan_id = scan_id
        proc.process = 'nmap'
        proc.command = 'nmap -sV -Pn -f --mtu 64 -p "*" -O ' + target_domain
        db.session.add(proc)
        db.session.commit()

    @staticmethod
    def run_nmscan(pid: int):
        """
        When run, queries the process information by the id provided from the database.
        Runs the test and returns the ouput of the test to the database
        :param pid: Id of process to run
        :return: None
        """
        process = Process.query.filter_by(id=pid).first()
        scan = Scan.query.filter_by(id=process.scan_id).first()
        target_obj = Target.query.filter_by(id=scan.target_id).first()
        target = target_obj.domain
        nm = NmapProcess(targets=target, options="-sV -Pn -f --mtu 64 -p '*' -O")
        rc = nm.run_background()
        process.status = nm.state
        process.progress = nm.progress
        process.date_started = datetime.now().isoformat()
        db.session.commit()

        if nm.has_failed():
            process.output = "nmap scan failed: {0}".format(nm.stderr)
            db.session.commit()
            return 1

        while nm.is_running():
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,
                                                                  nm.progress))
            if int(scan.progress) < int(float(nm.progress)):
                process.progress = int(float(nm.progress))
                scan.progress = int(float(nm.progress))
                db.session.commit()
            sleep(5)

        process.date_completed = datetime.now().isoformat()
        scan.date_completed = datetime.now().isoformat()
        if nm.has_failed():
            process.status = nm.state
            scan.status = nm.state
            process.output = str(nm.stderr)
        elif nm.is_successful():
            process.status = 3
            scan.status = 3
            scan.progress = 100
            nmap_full_output = json.dumps(cb.data(fromstring(str(nm.stdout))))
            nmap_output = Nmap.parse_nmap_output(nmap_full_output)
            if nmap_output:
                process.output = json.dumps(nmap_output)
                scan.output = json.dumps(nmap_output)
            else:
                scan.output = None
        db.session.commit()

    @staticmethod
    def get_nmap_results(scan_id):
        all_ouputs = []
        open_ports = 0
        ip = ""
        os = ""
        scans = Scan.query.filter_by(id=scan_id).all()
        for process in scans:
            if process.scan_type == "nmap":
                output = json.loads(process.output)
                ip = output.get("address")
                os = output.get("os").get("name")
                port_list = output.get("ports")
                for port in port_list:
                    open_ports += 1
                    all_ouputs.append(NmapResult(port))
        return open_ports, ip, os, all_ouputs

    @staticmethod
    def parse_nmap_output(nmap_full_output) -> list or None:
        nmap_output = None
        os = None
        accuracy = 0
        port_list = []
        nmap_out_refining = json.loads(nmap_full_output).get("nmaprun").get("children")
        for entry in nmap_out_refining:
            if "host" in list(entry.keys()):
                nmap_host_info_list = entry.get("host").get("children")
                for dictionary in nmap_host_info_list:
                    key_list = list(dictionary.keys())
                    if "address" in key_list:
                        address_data = dictionary.get("address").get("attributes").get("addr")
                        port_data = dictionary.get("ports").get("children")
                        os_data = dictionary.get("os").get("children")

                        for port_dict in port_data:
                            port_dict_keys = list(port_dict.keys())
                            if "port" in port_dict_keys:
                                port = port_dict.get("port").get("attributes")
                                if port:
                                    port_num = port.get("portid", None)
                                    port_protocol = port.get("protocol", None)
                                    children = port_dict.get("port").get("children")
                                    for child in children:
                                        child_keys = list(child.keys())
                                        if "service" in child_keys:
                                            service = child.get("service").get("attributes")
                                            if service:
                                                service_name = service.get("name", None)
                                                service_product = service.get("product", None)
                                            port_list.append(
                                                {"port_num": port_num, "port_proto": port_protocol, "service": service_name,
                                                 "product": service_product})
                            else:
                                pass

                        for item in os_data:
                            keys_list = list(item.keys())
                            if "osmatch" in keys_list:
                                print(item)
                                new_accuracy = int(item.get("osmatch").get("attributes").get("accuracy"))
                                if new_accuracy > accuracy:
                                    accuracy = new_accuracy
                                    os = item.get("osmatch").get("attributes").get("name")
                                else:
                                    pass
                            else:
                                pass

                        nmap_output = {"address": address_data, "ports": port_list,
                                       "os": {"name": os, "accuracy": accuracy}}
        return nmap_output


# DONT ADD THIS FUNCTION TO THE CALSS DIAGRAM
def test(target):
    nm = NmapProcess(targets=target, options="-sV -Pn -f -p '*' -O ")
    rc = nm.sudo_run_background()

    while nm.is_running():
        print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,
                                                              nm.progress))
        sleep(5)

    if nm.is_successful():
        try:
            parsed = NmapParser.parse(nm.stdout)
            print(parsed.summary)
            output = str(nm.stdout)
            print(output)
        except NmapParserException as e:
            print("Exception raised while parsing scan: {0}".format(e.msg))
    else:
        out = str(nm.stderr)
        print(out)


if __name__ == '__main__':
    test("setloki.com")
