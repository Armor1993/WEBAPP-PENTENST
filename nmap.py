from libnmap.process import NmapProcess
from datetime import datetime
from time import sleep
from libnmap.parser import NmapParser, NmapParserException
from app import db, Process, Scan, Target

# DONE list of open ports
# DONE services running on ports
# TODO operating system of the scanned machine
# DONE Retreive scan progress and status
# DONE store results or progress states in PROCESS db


class Nmap:

    @staticmethod
    def create_nmprocess(scan_id):
        # query the database to get the domain out of the connected scan and target tables
        target_scan = Scan.query.get(id=scan_id)
        target_domain = Target.query.get(id=target_scan.target_id).domain
        # Create new process object
        proc = Process()
        proc.scan_id = scan_id
        proc.process = 'nmap'
        proc.command = 'nmap, -sV -p "*" ' + target_domain
        db.session.add(proc)
        db.session.commit()

    @staticmethod
    def run_nmscan(target, pid: int):
        process = Process.query.get(id=pid)
        nm = NmapProcess(targets=target, options="-sV -Pn -f --mtu 64 -p '*' -O")
        rc = nm.run_background()
        process.status = nm.state
        process.progress = nm.progress
        process.date_started = nm.starttime
        db.session.comit()

        if rc != 0:
            process.output = "nmap scan failed: {0}".format(nm.stderr)
            db.session.commit()
            return 1

        while nm.is_running():
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,
                                                                  nm.progress))
            process.progress = nm.progress
            db.session.commit()
            sleep(5)

        process.date_completed = datetime.now().isoformat()
        if nm.has_failed():
            process.status = nm.state
            process.output = str(nm.stderr)
        elif nm.is_successful():
            process.output = str(nm.stdout)
        db.session.commit()


def parse_scan(nm_report)-> dict:
    ret = {}
    for host in nm_report.hosts:
        if len(host.hostnames):
            hname = host.hostname.pop()
        else:
            hname = host.address
        ret[hname] = {"started": nm_report.started, "address": host.address}
        ret[hname]["ports"] = []
        for serv in host.services:
            ret[hname]["ports"].append({serv.port: {"proto": serv.protocol,
                                                    "state": serv.state,
                                                    "service": serv.service}})
        if host.os_fingerprinted:
            ret[hname]["os_guess"] = []
            for osm in host.os.osmatches:
                ret[hname]["os_guess"].append({osm.name: {"accuracy": osm.accuracy}})
                for cpe in osm.get_cpe():
                    ret[hname]["os_guess"][osm.name]["cpe"] = cpe
    return ret


def test(target):
    nm = NmapProcess(targets=target, options="-sV -Pn -f --mtu 64 -p '*' -O ")
    rc = nm.sudo_run_background()

    while nm.is_running():
        print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,
                                                              nm.progress))
        sleep(5)

    if nm.is_successful():
        try:
            parsed = NmapParser.parse(nm.stdout)
            out_dict = parse_scan(parsed)
            print("MY DICTIONARY:\n")
            print(out_dict)
            print("SUMMARY:\n")
            print(parsed.summary)
        except NmapParserException as e:
            print("Exception raised while parsing scan: {0}".format(e.msg))
    #     output = str(nm.stdout)
    #     print(output)
    else:
        out = str(nm.stderr)
        print(out)


if __name__ == '__main__':
    test("iyte.edu.tr")