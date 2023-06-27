import re
import pandas as pd
import yaml
from PrivacyScope import PrivacyScope, load_scopes, save_scopes
from FileUtil import getFilenames


def df_to_ts(df, time_col='frame.time'):
    df.loc[:, 'count'] = 1
    tmp = df.set_index(time_col).infer_objects()
    tmp = tmp.resample('1S').sum(numeric_only=True).infer_objects()
    return tmp.reset_index()


def get_GNS3_offset():
    # Read the YAML file
    with open('data/experiment0-0.01/shadow.config.yaml', 'r') as file:
        data = yaml.safe_load(file)

    # Extract the value
    time = data['hosts']['group0user0']['processes'][2]['args'].split()[1]
    return int(time)


def get_start_time(scopes):
    df = pd.concat([scope.as_df() for scope in scopes])
    start_time = df.head(1).index.to_numpy()[0]
    return pd.to_datetime(start_time)


def time_scale(cache=False):
    # Get argus data
    arguspath = "data/argus/csv/"
    argusCSVs = getFilenames(arguspath)

    # Get pcap data
    pcappath = "data/csv/"
    pcapCSVs = getFilenames(pcappath)

    # Get server logs
    logpath = "data/experiment0-0.01/shadow.data/hosts/mymarkovservice0/"
    logs = getFilenames(logpath)

    # Combine all locations
    data = argusCSVs + pcapCSVs + logs

    # Basic Scopes

    # Get all clients and ISP dns scope
    r = re.compile(r".*isp.csv|.*group[0-9]*user[0-9]*-(?!127\.0\.0\.1)[0-9]*.[0-9]*.[0-9]*.[0-9]*..csv")
    ISP_scope = PrivacyScope(list(filter(r.match, data)), "ISP")


    # Access to public resolver scope
    r = re.compile(r".*isp.*.csv")
    Access_resolver = PrivacyScope(list(filter(r.match, data)), "Access_resolver")

    r = re.compile(r"(.*tld).*.csv")
    tld = PrivacyScope(list(filter(r.match, data)), "TLD")

    r = re.compile(r"(.*root).*.csv")
    root = PrivacyScope(list(filter(r.match, data)), "root")

    r = re.compile(r"(.*sld).*.csv")
    sld = PrivacyScope(list(filter(r.match, data)), "SLD")

    # Access Tor Scope
    r = re.compile(r".*group[0-9]*user[0-9]*-(?!127\.0\.0\.1)[0-9]*.[0-9]*.[0-9]*.[0-9]*..csv")
    Access_tor = PrivacyScope(list(filter(r.match, data)), "Access_tor")

    # Server Public Scope
    r = re.compile(r".*myMarkovServer0*-(?!127\.0\.0\.1)[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*.csv")
    Server_scope = PrivacyScope(list(filter(r.match, data)), "Server_of_interest")

    # tor Exit scope
    r = re.compile(r".*exit.*")
    Tor_exit_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_exit")

    # tor Guard scope
    r = re.compile(r".*guard.*")
    Tor_guard_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_guard")

    # tor Relay scope
    r = re.compile(r".*relay.*")
    Tor_relay_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_relay")

    # tor Middle scope
    r = re.compile(r".*middle.*")
    Tor_middle_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_middle")

    # tor 4uthority scope
    r = re.compile(r".*4uthority.*")
    Tor_4uthority_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_4uthority")

    # resolver scope
    r = re.compile(r".*resolver.*")
    resolver = PrivacyScope(list(filter(r.match, data)), "resolver")

    GNS3_scopes = [resolver,
                   sld,
                   tld,
                   root]

    GNS3_offset = get_GNS3_offset()
    scale = 10
    for scope in GNS3_scopes:
        scope.pcap_df()
        scope.adjust_time_scale(GNS3_offset, scale)
    GNS3_starttime = get_start_time(GNS3_scopes)

    Access_resolver.pcap_df()
    Access_resolver.adjust_time_scale(GNS3_offset, scale)

    ar = Access_resolver.as_df()
    ar = ar[(ar['ip.proto'] == 6) & (ar['tcp.dstport'] == 80) & (ar['ip.len']>200)]
    start_http = ar.index.min()
    delay = start_http - GNS3_starttime

    # service log scope
    r = re.compile(".*mymarkovservice*.*py.*stdout")
    chatlog = PrivacyScope(list(filter(r.match, data)), "chatlogs")
    chatlog.time_col = "time"
    chatlog.time_cut_tail = 0
    chatlog.time_format = 'epoch'
    # Subtract an extra second for buffer room to ensure chatlog happens after DNS
    chatlog.set_index(chatlog.time_col)
    Shadow_offset = GNS3_starttime - chatlog.start_time() + delay
    chatlog.set_offset(Shadow_offset)

    print("GNS3_starttime: " + str(GNS3_starttime))
    print("chatlog.start_time(): " + str(chatlog.start_time()))

    # Ensure chat happens after DNS traffic
    assert chatlog.start_time() - GNS3_starttime > pd.Timedelta(seconds=0)
    assert chatlog.start_time() - ar.index.min() == pd.Timedelta(seconds=0)
    if cache:
        save_scopes(GNS3_scopes, "time_scaled")
    return GNS3_scopes, Shadow_offset


if __name__ == "__main__":
    GNS3_scopes = time_scale(cache=True)
    GNS3_scopes_names = [scope.name for scope in GNS3_scopes]
    GNS3_scopes = load_scopes(GNS3_scopes_names, "time_scaled")
