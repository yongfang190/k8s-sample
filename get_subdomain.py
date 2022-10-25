import argparse
import datetime
import logging
import json
import os
import queue
import time
import requests
import sys
import threading
# sys.path.append("..")
from qianxin_passive_dns import query_qianxin_passive_dns

global_lock = threading.Lock()
global_pdns_count = 0
global_unique_domains = set()

def req(url,headers,timeout=80):
    i = 0
    list=[]
    while i<1:
        try:
            r = requests.get(url,headers=headers,timeout=timeout)
            return r.text
        except requests.exceptions.RequestException:
            logging.info("timeout%d%s",i,url)
            i+=1
    return list

def get_subdomain(
    domains,
    end_time,
    data_dir,
    headers,
    rtype=-1,
    limit=-1,
    mode=5,
    days=30,
):
    start_time = end_time - datetime.timedelta(days=days)
    interval=16                      #the init interval is 16 hour
    today = datetime.date.today().strftime("%Y%m%d")
    while not domains.empty():
        domain=domains.get()
        with open(data_dir +today+'/'+ domain + '.json', 'w',newline='\n') as subdomain_file:
                frist_time = start_time
                next_time = frist_time + datetime.timedelta(hours=interval)
                while   frist_time < end_time:
                    url = 'https://api.secrank.cn/flint/rrset/*.' + domain + '/?' + 'limit=' + str(
                        limit) + '&rtype=' + str(rtype) + '&start=' + str(frist_time.strftime("%Y%m%d%H%M%S")) + '&end=' + str(next_time.strftime("%Y%m%d%H%M%S")) + '&mode=' + str(
                        mode)

                    rtext = req(url,headers)

                    try:
                        text = json.loads(rtext)
                        for item in text['data']:
                            itemdata = json.dumps(item)
                            subdomain_file.write(itemdata + '\n')

                        interval *= 2
                        frist_time = next_time
                        next_time = frist_time+datetime.timedelta(hours=interval)
                    except Exception as ex:
                        if interval <= 1/30 :
                            logging.info(rtext)
                            logging.info(url)
                            frist_time = next_time
                            next_time = frist_time + datetime.timedelta(hours=interval)
                        else:
                            interval = interval / 4
                            next_time = frist_time + datetime.timedelta(hours=interval)

        logging.info("%s already", domain)

class PDNSThread(threading.Thread):
    def __init__(
        self,
        domain_queue,
        # start_datetime,
        # end_datetime,
        result_dir,
        pdns_token,
    ):
        super().__init__()
        self.domain_queue = domain_queue
        # self.start_datetime = start_datetime
        # self.end_datetime = end_datetime
        self.result_dir = result_dir
        self.pdns_token = pdns_token

    def run(self):
        global global_lock
        global global_pdns_count
        global global_unique_domains
        logging.info("start thread %s",self.name)
        while not self.domain_queue.empty():
            domain, start_datetime, end_datetime = self.domain_queue.get()
            domain_regexp = f"*.{domain}"
            with open(
                os.path.join(self.result_dir, f"{domain}_{start_datetime}_{end_datetime}.json"),
                "w"
            ) as fd:
                result_entries = query_qianxin_passive_dns(
                    domain_regexp=domain_regexp,
                    start_datetime=start_datetime,
                    end_datetime=end_datetime,
                    api_token=self.pdns_token,
                )
                for entry in result_entries:
                    fd.write(json.dumps(entry) + "\n")
                global_lock.acquire()
                for entry in result_entries:
                    global_pdns_count += 1
                    global_unique_domains.add(entry["rrname"])
                global_lock.release()
        logging.info("end thread: %s",self.name)

def split_time_windows(
    start_datetime: datetime.datetime,
    end_datetime: datetime.datetime,
    window_size: datetime.timedelta=datetime.timedelta(days=30),
    datetime_format="%Y%m%d%H%M%S",
):
    result_time_windows = []
    curr_datetime = start_datetime
    while curr_datetime < end_datetime:
        next_datetime = curr_datetime + window_size
        if next_datetime > end_datetime:
            next_datetime = end_datetime
        result_time_windows.append((
            curr_datetime.strftime(datetime_format),
            next_datetime.strftime(datetime_format)
        ))
        curr_datetime = next_datetime
    return result_time_windows

if __name__ == "__main__":
    """ 
    1) load the config file
    2) load the domain names
    3) for each domain name, query its pdns records
    """
    logging.basicConfig(level=logging.INFO, format="%(threadName)s %(asctime)s %(levelname)s %(message)s")
    start_time = time.time()
    # the date format required by the passive DNS api
    datetime_format = "%Y%m%d%H%M%S"
    default_end_date_str = datetime.datetime.now().strftime(datetime_format)
    default_start_date_str = (datetime.datetime.now() - datetime.timedelta(days=7)).strftime(datetime_format)
    parser = argparse.ArgumentParser("Passive DNS Crawler")
    parser.add_argument("domain_file", type=str)
    parser.add_argument("result_dir", type=str, help="the directory to store resulting pDNS datasets")
    parser.add_argument("pdns_token_file", type=str)
    parser.add_argument("--is_domain", "-id", action="store_true", help="Given if the first arg is a domain")
    parser.add_argument(
        "--end_datetime",
        "-ed",
        default=default_end_date_str,
        type=str,
        help=f"The ending datetime in string, and the default is {default_end_date_str}",
    )
    parser.add_argument(
        "--start_datetime",
        "-sd",
        default=default_start_date_str,
        type=str,
        help=f"The start datetime in string, and the default is {default_start_date_str}",
    )
    parser.add_argument("--time_window_in_days", "-twd", default=30, type=int)
    parser.add_argument("--thread_count", "-tc", default=5, type=int)
    options = parser.parse_args()
    assert options.time_window_in_days >= 1, "time window should be at least 1 days"
    if not os.path.exists(options.result_dir):
        os.makedirs(options.result_dir)
    domains = set()
    pdns_token = open(options.pdns_token_file, "r").read().strip()
    if options.is_domain:
        domains.add(options.domain_file)
    else:
        domains |= set(open(options.domain_file, "r").read().splitlines())
    logging.info("Got %d domains for pDNS query", len(domains))
    start_datetime = datetime.datetime.strptime(options.start_datetime, datetime_format)
    end_datetime = datetime.datetime.strptime(options.end_datetime, datetime_format)
    time_windows = split_time_windows(
        start_datetime,
        end_datetime,
        datetime_format=datetime_format,
        window_size=datetime.timedelta(days=options.time_window_in_days),
    )
    logging.info("Got %d time windows", len(time_windows))
    threads = []
    domain_queue = queue.Queue()
    for domain in domains:
        for tw_start, tw_end in time_windows:
            domain_queue.put((domain, tw_start, tw_end))   
    thread_count = options.thread_count if options.thread_count < domain_queue.qsize() else domain_queue.qsize()
    for i in range(thread_count):
        thread = PDNSThread(
            domain_queue=domain_queue,
            pdns_token=pdns_token,
            result_dir=options.result_dir,
        )
        threads.append(thread)
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    with open(os.path.join(options.result_dir, "unique_domains.txt"), "w") as fd:
        for domain in global_unique_domains:
            fd.write(f"{domain}\n")
    end_time = time.time()
    logging.info(
        "End with %d domains queried,and  a time cost of %d seconds",
        len(domains),
        end_time - start_time,
    )
    logging.info(
        "End with %d pdns records captured, and %d unique domains observed",
        global_pdns_count,
        len(global_unique_domains),
    )