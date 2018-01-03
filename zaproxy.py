import time
from datetime import datetime
from pprint import pprint
from zapv2 import ZAPv2
from app import db, Process, Target, Scan

apikey = '1baf49842fb49da4'

# TODO Add ZAP output parser


class Zap:
    """
     Creates and runs the Zap scan
    """

    @staticmethod
    def create_process(scan_id):
        """
        Creates a Process object for the scan id provided; and adds it to the database
        :param scan_id: Id of the scan object that is related to the process
        :return: None

        """

        # query the database to get the domain out of the connected scan and target tables
        target_scan = Scan.query.get(id=scan_id)
        target_domain = Target.query.get(id=target_scan.target_id).domain
        # Create new process object
        if 'http://' in target_domain or 'https://' in target_domain:
            proc = Process()
            proc.scan_id = scan_id
            proc.process = 'zap'
            proc.command = target_domain
            db.session.add(proc)
            db.session.commit()
        else:
            proc = Process()
            proc2 = Process()
            proc.scan_id = scan_id
            proc2.scan_id = scan_id
            proc.process = 'zap'
            proc2.process = 'zap'
            proc.command = 'http://'+target_domain
            proc2.command = 'https://'+target_domain
            db.session.add(proc)
            db.session.add(proc2)
            db.session.commit()

    @staticmethod
    def start_zscan(pid: int):
        """
        When run, queries the process information by the id provided from the database.
        Runs the test and returns the ouput of the test to the database
        :param pid: Id of process to run. Also used to get the target domain through database relation
        :return: None
        """
        zap = ZAPv2()
        proc = Process.query.get(id=pid)
        command = proc.command
        zap.urlopen(command)
        proc.status = 1
        proc.date_started = datetime.now().isoformat()
        db.session.commit()
        time.sleep(2)
        scanid = zap.spider.scan(command)
        proc.status = 1
        db.session.commit()
        while int(zap.spider.status(scanid)) < 100:
            proc.progress = zap.spider.status(scanid)
            db.session.commit()
            time.sleep(5)
        time.sleep(5)
        scanid = zap.ascan.scan(command)
        proc.status = 2
        db.session.commit()
        while int(zap.ascan.status(scanid)) < 100:
            proc.progress = zap.ascan.status(scanid)
            db.session.commit()
            time.sleep(5)
        proc.status = 3
        proc.output = str((zap.core.alerts()))
        proc.progress = 100
        db.session.commit()

    @staticmethod
    def report_parser(zap_out: str)-> dict:
        """
        Given the string output of ZAP scan. The function converts the output into a dictionary and saves it to the database
        :param zap_out: Zap scan output
        :return: dict
        """
        # TODO
        pass


# DONT ADD TO CLASS DIAGRAM
def test():
    # By default ZAP API client will connect to port 8080
    zap = ZAPv2(apikey=None)
    target = 'http://setloki.com'
    # Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
    # zap = ZAPv2(apikey=apikey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})

    # do stuff
    print('Accessing target %s' % target)
    # try have a unique enough session...
    zap.urlopen(target)
    # Give the sites tree a chance to get updated
    time.sleep(10)

    print('Spidering target %s' % target)
    scanid = zap.spider.scan(target)
    # Give the Spider a chance to start
    time.sleep(10)
    while int(zap.spider.status(scanid)) < 100:
        print('Spider progress %: ' + zap.spider.status(scanid))
        time.sleep(5)

    print('Spider completed')
    # Give the passive scanner a chance to finish
    time.sleep(5)

    print('Scanning target %s' % target)
    scanid = zap.ascan.scan(target)
    while int(zap.ascan.status(scanid)) < 100:
        print('Scan progress %: ' + zap.ascan.status(scanid))
        time.sleep(5)

    print('Scan completed')

    # Report the results

    print('Hosts: ' + ', '.join(zap.core.hosts))
    print('Alerts: ')
    pprint(zap.core.alerts())
