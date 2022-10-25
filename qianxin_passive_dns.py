from datetime import datetime
import json
import logging
import requests
def query_qianxin_passive_dns(
    domain_regexp,
    api_token,
    start_ts=None,
    end_ts=None,
    start_datetime=None,
    end_datetime=None,
    record_cap=-1,
    limit=500,
    retry_cap=3,
    rtype=-1, # all DNS record types
    mode=7, # all records ever active during the given period
):
    date_format = "%Y%m%d%H%M%S"
    resp_entries = []
    last_key = None
    retry_count = 0
    cumu_failure_count = 0
    headers = {
        "fdp-token": api_token,
    } 
    if start_datetime is None:
        start_datetime =  datetime.fromtimestamp(start_ts).strftime(date_format)
    if end_datetime is None:
        end_datetime =  datetime.fromtimestamp(end_ts).strftime(date_format)
    get_params = {
        "limit": limit,
        "rtype": rtype,
        "mode": mode,
        "start": start_datetime,
        "end": end_datetime,
        "lastkey": "",
    
    }   
    url = f"https://api.secrank.cn/flint/rrset/{domain_regexp}"
    unique_domains = set()
    while (record_cap == -1) or len(resp_entries) < record_cap:
        if last_key is not None:
            get_params.update({"lastkey": last_key})
        try:
            # print(url, get_params, headers)
            resp = requests.get(url,params=get_params, headers=headers, timeout=30)
            if resp.status_code != 200:
                logging.info(
                    "Got non-200 resp with message %s",
                    resp.status_code,
                    resp.text,
                )
                cumu_failure_count += 1
                if  retry_count >= retry_cap:
                    logging.info("Failed with more than %d retries", retry_count)
                    break
                retry_count += 1
                continue
            else:
                resp_obj = json.loads(resp.text)
                entries = resp_obj["data"]
                new_key = resp_obj.get("lastKey", None)
                if len(entries) == 0 and (
                    new_key is None or len(new_key) == 0
                ):
                    if  retry_count >= retry_cap:
                        logging.info("Failed with more than %d retries, and confirmed no more entries", retry_count)
                        break
                    else:
                        retry_count += 1
                        continue
                for entry in entries:
                    rrname = entry["rrname"]
                    unique_domains.add(rrname)
                resp_entries.extend(entries)
                retry_count = 0  
                last_key = new_key
                logging.info(
                    "Round: %d entries in current round, %d in total, %d unique domains in total",
                    len(entries),
                    len(resp_entries),
                    len(unique_domains),
                )
        except Exception as e:
            logging.warning("Got error %s when retrying the %d times", e, retry_count)
            cumu_failure_count += 1
            if  retry_count >= retry_cap:
                logging.info("Failed with more than %d retries", retry_count)
                break
            retry_count += 1
            continue
    logging.info(
        "Got %d entries, with %d cumulative failures",
        len(resp_entries),
        cumu_failure_count,
    )
    return resp_entries