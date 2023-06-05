import bisect
import yaml
from datetime import datetime
import re
import sys
from PrivacyScopes import getFilenames


class TimestampedDict:
    def __init__(self):
        self.dict = {}
        self.timestamps = {}

    def add(self, key, timestamp, value):
        if key in self.dict:
            self.dict[key][timestamp] = value
        else:
            self.dict[key] = {}
            self.dict[key][timestamp] = value
        if key in self.timestamps:
            bisect.insort(self.timestamps[key], timestamp)
        else:
            self.timestamps[key] = [timestamp]
        return self

    def get(self, key, timestamp):
        if key not in self.dict or key not in self.timestamps:
            return None
        values = self.dict[key]
        timestamps = self.timestamps[key]
        if values and timestamps:
            index = bisect.bisect_right(timestamps, timestamp)
            if index > 0:
                return values[self.timestamps[key][index - 1]]
            else:
                return None
        else:
            return None

    def latest(self, key):
        if key not in self.timestamps:
            return None
        timestamps = self.timestamps[key]
        if timestamps:
            return timestamps[-1]
        else:
            return None

    def latest_value(self, key):
        timestamp = self.latest(key)
        if timestamp is None:
            return None
        return self.get(key, timestamp)

    def add_if_new(self, key, timestamp, value):
        latest = self.latest_value(key)
        if latest != value:
            self.add(key, timestamp, value)


def read_oniontraces():
    onion_path = "data/experiment0-0.01/shadow.data/hosts"
    onion_files = getFilenames(onion_path)

    r = re.compile(r".*group\d+user\d+\.oniontrace\.\d+\.stdout")
    onion_files = list(filter(r.match, onion_files))
    logs = {}
    for f in onion_files:
        hostname = f.split('/')[-1].split('.')[0]
        with open(f, 'r') as file:
            logs[hostname] = file.readlines()
    return logs


def filter_log(user_logs, circ_regex):
    output = {}
    pattern = re.compile(circ_regex)
    for user in user_logs:
        filtered_lines = [line for line in user_logs[user]
                          if pattern.match(line)]
        output[user] = filtered_lines
    return output


def parse_onion_trace(line):
    pattern = r"CIRC \d+ EXTENDED \$[0-9A-Z]+~([a-zA-Z0-9]+),.*,\$[0-9A-Z]+~([0-9A-Za-z]+).*TIME_CREATED=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+)"

    match = re.search(pattern, line)
    if match:
        entry = match.group(1)
        exit = match.group(2)
        timestamp = match.group(3)
        timestamp_parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")
        return timestamp_parsed, entry, exit
    else:
        print(line)
        print("bad line!!!!")
        sys.exit(1)


def onion_map_maker():
    # Read the file
    config = 'data/experiment0-0.01/shadow.data/processed-config.yaml'
    with open(config, 'r') as file:
        data = yaml.safe_load(file)

    hosts_dict = {}

    # Extract the name and IP address of each host
    for host_name, host_data in data['hosts'].items():
        ip_addr = host_data['ip_addr']
        hosts_dict[host_name] = ip_addr
    return hosts_dict


def convert_to_map(logs, offset):
    onion_lut = onion_map_maker()
    tor_ip_map_src = TimestampedDict()
    tor_ip_map_dst = TimestampedDict()
    for user in logs:
        for line in logs[user]:
            timestamp, entry, exit = parse_onion_trace(line)
            timestamp += offset
            entry_ip = onion_lut[entry]
            exit_ip = onion_lut[exit]
            tor_ip_map_src.add_if_new(user, timestamp, entry_ip)
            tor_ip_map_dst.add_if_new(user, timestamp, exit_ip)
    return tor_ip_map_src, tor_ip_map_dst


def generate_tor_maps(Shadow_offset):
    circ_regex = r".*CIRC \d+ EXTENDED \$([0-9A-Za-z~]+),.*,\$([0-9A-Za-z~]+).*TIME_CREATED=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+)"
    user_logs = read_oniontraces()
    filtered_logs = filter_log(user_logs, circ_regex)

    return convert_to_map(filtered_logs, Shadow_offset)
