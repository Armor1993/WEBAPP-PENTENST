from libnmap.process import NmapProcess
from datetime import datetime
from time import sleep
from libnmap.parser import NmapParser, NmapParserException
from app import db, Process, Scan, Target

# TODO operating system of the scanned machine
# TODO Write XML Parser for output
# TODO Create Nmap object for xml parser to fill


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
        """
        When run, queries the process information by the id provided from the database.
        Runs the test and returns the ouput of the test to the database
        :param target: The target to be scanned
        :param pid: Id of process to run
        :return: None
        """
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


    @staticmethod
    def xml_parse(xmlstr: str) -> dict:
        """
        Parse the xml output of the nmap scan and create a dictionary of the scan findings
        :param xmlstr: xml string output of the scan
        :return: Dict
        """
        # TODO
        pass


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
