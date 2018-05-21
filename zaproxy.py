import time
from pprint import pprint
from zapv2 import ZAPv2
from environment import *
import json
apikey = '1tji9t090d0eak9gr84qv835c0'


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
        target_scan = Scan.query.filter_by(id=scan_id).first()
        target_domain = Target.query.filter_by(id=target_scan.target_id).first().domain
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
        proc = Process.query.filter_by(id=pid).first()
        scan = Scan.query.filter_by(id=proc.scan_id).first()
        command = proc.command
        zap.urlopen(command)
        proc.status = 1
        proc.date_started = datetime.now().isoformat()
        scan.date_started = datetime.now().isoformat()
        db.session.commit()
        time.sleep(2)
        scanid = zap.spider.scan(command)
        db.session.commit()
        while int(zap.spider.status(scanid)) < 100:
            proc.progress = zap.spider.status(scanid)
            scan.progress = zap.spider.status(scanid)
            db.session.commit()
            time.sleep(5)
        time.sleep(5)
        scanid = zap.ascan.scan(command)
        proc.status = 2
        db.session.commit()
        while int(zap.ascan.status(scanid)) < 100:
            proc.progress = zap.ascan.status(scanid)
            scan.progress = zap.spider.status(scanid)
            db.session.commit()
            time.sleep(5)
        proc.status = 3
        scan.status = 3
        zap_out = zap.core.alerts()
        result_count = 0
        for output in zap_out:
            result_count += 1
            new_result = ZapOutputs()
            new_result.scan_id = scan.id
            new_result.pid = pid
            new_result.result = json.dumps(output)
            new_result.result_num = result_count
            db.session.add(new_result)
        proc.progress = 100
        scan.progress = 100
        scan.date_completed = datetime.now().isoformat()
        db.session.commit()

    @staticmethod
    def get_zap_scan_outputs(scan_id):
        # zap_processes = []
        all_ouputs = []
        critical = 0
        warning = 0
        info = 0
        processes = ZapOutputs.query.filter_by(scan_id=scan_id).all()
        for process in processes:
            result = ZapResult(json.loads(process.result))
            result.result_num = process.id
            # out_list = list(process.output)
            if result.risk == "Low":
                info += 1
            elif result.risk == "Medium":
                warning += 1
            elif result.risk == "High":
                critical += 1
            all_ouputs.append(result)
        return all_ouputs, critical, warning, info
