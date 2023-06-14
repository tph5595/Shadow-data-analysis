from PrivacyScopes import getFilenames, PrivacyScope, align_times, \
        solo_pipeline, scopeToTS, combineScopes, scope_label
from Metrics import get_real_label
from TorRewrite import onion_map_maker, generate_tor_maps
import re
import pandas as pd

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

df = pd.read_csv(pcapCSVs[0])
# Basic Scopes

# Get all clients and ISP dns scope
r = re.compile(r".*isp.csv|.*group[0-9]*user[0-9]*-(?!127\.0\.0\.1)[0-9]*.[0-9]*.[0-9]*.[0-9]*..csv")
isp_scope = PrivacyScope(list(filter(r.match, data)), "ISP")

# Access to public resolver scope
r = re.compile(r".*isp.*.csv")
access_resolver = PrivacyScope(list(filter(r.match, data)), "Access_resolver")

r = re.compile(r"(.*tld).*.csv")
tld = PrivacyScope(list(filter(r.match, data)), "TLD")

r = re.compile(r"(.*root).*.csv")
root = PrivacyScope(list(filter(r.match, data)), "root")

r = re.compile(r"(.*sld).*.csv")
sld = PrivacyScope(list(filter(r.match, data)), "SLD")

# Access Tor Scope
r = re.compile(r".*group[0-9]*user[0-9]*-(?!127\.0\.0\.1)[0-9]*.[0-9]*.[0-9]*.[0-9]*..csv")
access_tor = PrivacyScope(list(filter(r.match, data)), "Access_tor")

# Server Public Scope
r = re.compile(r".*myMarkovServer0*-(?!127\.0\.0\.1)[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*.csv")
server_scope = PrivacyScope(list(filter(r.match, data)), "Server_of_interest")

# tor Exit scope
r = re.compile(r".*exit.*")
tor_exit_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_exit")

# tor Guard scope
r = re.compile(r".*guard.*")
tor_guard_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_guard")

# tor Relay scope
r = re.compile(r".*relay.*")
tor_relay_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_relay")

# tor Middle scope
r = re.compile(r".*middle.*")
tor_middle_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_middle")

# tor 4uthority scope
r = re.compile(r".*4uthority.*")
tor_4uthority_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_4uthority")

# resolver scope
r = re.compile(r".*resolver.*")
resolver = PrivacyScope(list(filter(r.match, data)), "resolver")

GNS3_scopes = [access_resolver,
               sld,
               tld,
               root]
Shadow_offset = align_times(GNS3_scopes)

# service log scope
r = re.compile(".*mymarkovservice.*py.*stdout")
chatlog = PrivacyScope(list(filter(r.match, data)), "chatlogs")
chatlog.time_col = "time"
chatlog.time_cut_tail = 0
chatlog.time_format = 'epoch'
chatlog.set_offset(Shadow_offset)

window = pd.Timedelta("300 seconds")  # cache size but maybe smaller


def create_client_maps(src_map, dst_map):
    client_map = {}
    for client in src_map:
    return client_map


exit(1)
src_map, dst_map = generate_tor_maps()
access_resolver.ip_map(src_map, dst_map)
client_maps = create_client_maps(src_map, dst_map)

# Setup filters for different scopes
evil_domain = 'evil.dne'
DNS_PORT = 17.0
DOT_PORT = 853


def dns_filter(df, ip):
    if ('dns.qry.name' in df.columns and 'tcp.dstport' in df.columns):
        return df[(df['dns.qry.name'] == evil_domain)
                  | (df['dns.qry.name'].isna())
                  & (df['tcp.dstport'] == DOT_PORT)]
    else:
        return df[(df['dns.qry.name'] == evil_domain)
                  | (df['dns.qry.name'].isna())]


resolver.set_filter(dns_filter)
root.set_filter(dns_filter)
tld.set_filter(dns_filter)
sld.set_filter(dns_filter)

resolver.ip_search_enabled = True
resolver.cache_search_enabled = False

root.ip_search_enabled = True
root.cache_search_enabled = True

sld.ip_search_enabled = True
sld.cache_search_enabled = True

tld.ip_search_enabled = True
tld.cache_search_enabled = True

TCP_PROTO = 6


def tor_filter(df, ip):
    return df[(df['tcp.len'] > 500) & (df['ip.proto'] == TCP_PROTO)]


access_tor.set_filter(tor_filter)

access_tor.ip_search_enabled = True
access_tor.cache_search_enabled = True


# Cluster DNS
# Create ts for each IP
resolv_df = resolver.pcap_df()
resolv_df_filtered = resolv_df[resolv_df['tcp.dstport'] == DOT_PORT]
infra_ip = ['172.20.0.11', '172.20.0.12', '192.168.150.10', '172.20.0.10']
ips_seen = resolv_df_filtered['ip.src'].unique()
IPs = list(set(ips_seen) - set(infra_ip))
flows_ip = {}
flows_ts_ip_scoped = {}
flows_ts_ip_total = {}
first_pass = resolv_df_filtered[((~resolv_df_filtered['ip.src'].isin(infra_ip)))
                                & (resolv_df_filtered['dns.qry.name'] == evil_domain)]
solo = solo_pipeline(first_pass, window)

# Add all scope data to IPs found in resolver address space
# This should be a valid topo sorted list
# of the scopes (it will be proccessed in order)
scopes = [resolver, root, tld, sld]  # , Access_tor]
bad_features = ['tcp.dstport', 'tcp.srcport', 'udp.port', 'tcp.seq']
for scope in scopes:
    scope.remove_features(bad_features)
    scope.remove_zero_var()
cache_window = window  # see above
print("scopes: " + str(scopes))
print("cache window: " + str(cache_window))

for ip in IPs:
    # Don't add known infra IPs or users that can are solo communicaters
    if ip in infra_ip or ip in solo:
        continue
    flows_ip[ip] = pd.DataFrame()
    flows_ts_ip_scoped[ip] = pd.DataFrame()
    flows_ts_ip_total[ip] = pd.DataFrame()
    for scope in scopes:
        # Find matches
        matches = scope.search(ip, flows_ip[ip])

        # Update df for ip
        combined_scope = combineScopes(matches)
        combined_scope = scope_label(combined_scope, scope.name)
        combined_scope["scope_name"] = scope.name
        flows_ip[ip] = combineScopes([flows_ip[ip], combined_scope])

        # update ts for ip
        new_ts_matches = scopeToTS(combined_scope)
        if len(new_ts_matches) == 0:
            continue
        new_ts_matches["scope_name"] = scope.name
        flows_ts_ip_scoped[ip] = combineScopes([flows_ts_ip_scoped[ip],
                                                new_ts_matches])
    if len(flows_ip[ip]) > 0:
        flows_ts_ip_total[ip] = scopeToTS(flows_ip[ip])

        # order df by time
        flows_ip[ip] = flows_ip[ip].set_index('frame.time')

        # sort combined df by timestamp
        flows_ip[ip].sort_index(inplace=True)
        flows_ts_ip_scoped[ip].sort_index(inplace=True)
        flows_ts_ip_total[ip].sort_index(inplace=True)

        # Preserve time col to be used for automated feautre engineering
        flows_ip[ip]['frame.time'] = flows_ip[ip].index
        flows_ts_ip_total[ip]['frame.time'] = flows_ts_ip_total[ip].index

        # remove nans with 0
        flows_ip[ip].fillna(0, inplace=True)
        flows_ts_ip_scoped[ip].fillna(0, inplace=True)
        flows_ts_ip_total[ip].fillna(0, inplace=True)

        # label scope col as category
        flows_ip[ip]["scope_name"] = flows_ip[ip]["scope_name"].astype('category')
        flows_ts_ip_scoped[ip]["scope_name"] = flows_ts_ip_scoped[ip]["scope_name"].astype('category')

answers = get_real_label(flows_ts_ip_total)
