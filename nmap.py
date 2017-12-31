from libnmap.process import NmapProcess
from datetime import datetime
from time import sleep
from app import db, Process, Scan, Target

# DONE list of open ports
# DONE services running on ports
# TODO operating system of the scanned machine
# DONE Retreive scan progress and status
# DONE store results or progress states in PROCESS db


class NMAP:

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
        nm = NmapProcess(targets=target, options="-sV -p '*'")
        rc = nm.run_background()
        process.status = nm.state
        process.progress = nm.progress
        process.date_started = nm.starttime
        db.session.comit()

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