#!/usr/bin/env python
# coding: utf-8

# In[137]:


# get_ipython().system(' pip install pandas matplotlib')
# Knapsack NP complete could work
# or check for candidate DNSers that would be apart of the resource access and with enough resource access and DNS 
# could probably determine\


# What if determine candicate from DNSers like above but then look at their input to tor (frame size and timing 
# input and output with TDA to filter down candidates)


# In[138]:


# give shadow files old names

# import shutil
# import os
# import sys
# import re

# dr = "data/experiment0-0.0001"

# pattern = re.compile("^[0-9]*.[0-9]*.[0-9]*.[0-9]*..pcap")


# for root, dirs, files in os.walk(dr):
#     for file in files:
#         if pattern.match(file):
#             spl = root.split("/")
#             newname = spl[-1]
#             sup = ("/").join(spl[:-1])
#             shutil.move(root+"/"+file, sup+"/"+newname+"-"+file)


# In[139]:


# Get argus flows from PCAPs
#!../util/process_data_argus.sh


# In[140]:


# PCAP to CSV
#!../util/pcap_to_csv.sh


# In[141]:


# PCAPNG to CSV
#!../util/pcapng_to_csv.sh


# In[142]:


from os import listdir
from os.path import isfile, join

def getFilenames(path):
    return [path+f for f in listdir(path) if isfile(join(path, f))]


# In[143]:


# Get argus data
arguspath = "data/argus/csv/"
argusCSVs = getFilenames(arguspath)

# Get pcap data
pcappath = "data/csv/"
pcapCSVs = getFilenames(pcappath)
data = argusCSVs + pcapCSVs


# In[144]:


import pandas as pd


# In[145]:


df = pd.read_csv (pcapCSVs[0])
df


# In[146]:


len(data)


# In[147]:


len(argusCSVs)


# In[148]:


class PrivacyScope:

    def __init__(self, filenames, name):
        self.name = name
        self.filenames = filenames
        self.time_format = '%b %d, %Y %X.%f'
        self.time_col = 'frame.time'
        self.filter_func = lambda df, args: df
        self.df = None
        self.ip_search_enabled = False
        self.cache_search_enabled = False
        self.cache_timing = pd.Timedelta("300 seconds")
    
    def __str__(self):
        return "PrivacyScope(" + self.name + ")"

    def as_df(self, filenames=None):
        if self.df is not None:
            return self.df
        if filenames == None:
            filenames = self.filenames
        df = pd.DataFrame()
        for f in filenames:
            ddf = pd.read_csv (f)
            df = pd.concat([df, ddf])
        self.df = self.format_time_col(df)
        return self.df
        
    def get_ts(self):
        return None
    
    def format_time_col(self, df):
        df[self.time_col] = df[self.time_col].apply(lambda x: datetime.strptime(x[:-7], self.time_format))
        df.set_index(self.time_col)
        return df

    def pcap_only(self):
        r = re.compile(".*data/csv.*")
        return list(filter(r.match, self.filenames))
    
    def pcap_df(self):
        return self.as_df(filenames=self.pcap_only())
    
    def set_filter(self, filter_func):
        self.filter_func = filter_func
        
    def run_filter(self, args):
        return self.filter_func(self.as_df(), args)
    
    def filterByIP(self, ip, run_filter=True, args=None):
        df = self.as_df()
        if run_filter:
            df = self.run_filter(args)
        return df[((df['ip.dst'] == ip) | \
                                   (df['ip.src'] == ip))]

    def filterByCache(self, ip, cache_data, run_filter=True, args=None):
        df = self.as_df()
        if run_filter:
            df = self.run_filter(args)

        df_times = df[self.time_col].tolist()
        input_times = cache_data[self.time_col].tolist()
        keepers = [False] * len(df_times)
        idx = 0
        stop = len(input_times)
        for i in range(0, len(df_times)):
            if idx >= stop:
                break
            diff = input_times[idx] - df_times[i]
            if diff <= pd.Timedelta(0):
                idx += 1
            elif diff < self.cache_timing:
                keepers[i] = True
        
        return df[keepers]
    
    def search(self, ip=None, cache_data=None):
        matches = []
        if self.ip_search_enabled and ip is not None:
            matches += [self.filterByIP(ip)]
        if self.cache_search_enabled and cache_data is not None:
            matches += [self.filterByCache(ip, cache_data)]
        return matches


# In[149]:


# Basic Scopes
import re

# Get all clients and ISP dns scope
r = re.compile(".*isp.csv|.*group[0-9]*user[0-9]*-(?!127\.0\.0\.1)[0-9]*.[0-9]*.[0-9]*.[0-9]*..csv")
ISP_scope = PrivacyScope(list(filter(r.match, data)), "ISP")


# Access to public resolver scope
r = re.compile(".*isp.csv")
Access_resolver = PrivacyScope(list(filter(r.match, data)), "Access_resolver")

r = re.compile("(.*tld).csv")
tld = PrivacyScope(list(filter(r.match, data)), "TLD")

r = re.compile("(.*root).csv")
root = PrivacyScope(list(filter(r.match, data)), "root")

r = re.compile("(.*sld).csv")
sld = PrivacyScope(list(filter(r.match, data)), "SLD")

# Access Tor Scope
r = re.compile(".*group[0-9]*user[0-9]*-(?!127\.0\.0\.1)[0-9]*.[0-9]*.[0-9]*.[0-9]*..csv")
Access_tor = PrivacyScope(list(filter(r.match, data)), "Access_tor")

# Server Public Scope
r = re.compile(".*myMarkovServer0*-(?!127\.0\.0\.1)[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*.csv")
Server_scope = PrivacyScope(list(filter(r.match, data)), "Server_of_interest")

# tor Exit scope
r = re.compile(".*exit.*")
Tor_exit_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_exit")

# tor Guard scope
r = re.compile(".*guard.*")
Tor_guard_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_guard")

# tor Relay scope
r = re.compile(".*relay.*")
Tor_relay_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_relay")

# tor Middle scope
r = re.compile(".*middle.*")
Tor_middle_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_middle")

# tor 4uthority scope
r = re.compile(".*4uthority.*")
Tor_4uthority_Scope = PrivacyScope(list(filter(r.match, data)), "Tor_4uthority")

# resolver scope
r = re.compile(".*resolver.*")
resolver = PrivacyScope(list(filter(r.match, data)), "resolver")


# In[150]:


from datetime import datetime

def df_to_ts(df):
    df['count'] = 1
    #  Minute is T
    tmp = df.set_index('frame.time').infer_objects()
#     print("1:\t" + str(tmp))
    tmp = tmp.resample('3S').sum(numeric_only=True).infer_objects()
#     print("2:\t" + str(tmp))
    #tmp = tmp.rolling(10).sum(numeric_only=True)
    #print("3:\t" + str(tmp))
    return tmp.reset_index()


# In[151]:


# get start time for GNS3
GNS3_data = pd.concat([Access_resolver.pcap_df(), sld.pcap_df(), tld.pcap_df(), root.pcap_df()])
GNS3_starttime = GNS3_data.head(1)['frame.time'].tolist()[0]
Shadow_starttime = datetime.strptime('Dec 31, 1969 19:30:00', '%b %d, %Y %X')
Shadow_offset = GNS3_starttime - Shadow_starttime
Shadow_offset


# In[ ]:


#dns_df = Access_to_auth_zone.pcap_df()


# In[ ]:


window = pd.Timedelta("300 seconds") # cache size but maybe smaller 

# detect and remove solo quries
# these can easily be handled on their own as only 1 device is accessing the network at that moment
def detect_solo(df_list):
    new_df = df_list[df_list['ip.src'].ne(df_list['ip.src'].shift())]
    new_df['diff'] = new_df['frame.time'].diff()
    new_df = new_df[new_df['diff'] > window]
    solo_ips = new_df['ip.src'].unique()
    return solo_ips

def handle_solo(solo):
    print("IPs that must trigger a cache miss: " + str(solo))
    
def solo_pipeline(df_list):
    fil = df_list[['ip.src', 'frame.time']]
    solo = detect_solo(fil)
    handle_solo(solo)
    return solo


# In[ ]:


def combineScopes(dfs):
    if len(dfs) < 1:
        return dfs
    return pd.concat(dfs)

def scopesToTS(dfs):
    output = []
    for df in dfs:
        if len(df) < 2:
            continue
        output += scopeToTS(df)
    return output
def scopeToTS(df):
    return df_to_ts(df.copy()).set_index('frame.time')


# In[ ]:


def scope_label(df, scope_name):
    for col in df.columns:
        df[col + "_" + scope_name] = df[col]
    df["scope_name"]=scope_name
    return df


# In[ ]:


# Setup filters for different scopes
evil_domain = 'evil.dne'
DNS_PROTO = 17.0

dns_filter = lambda df, ip: df[(df['dns.qry.name'] == evil_domain )
                                            | (df['dns.qry.name'] == "") & (df['ip.proto'] == DNS_PROTO)]
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


# In[ ]:


# Cluster DNS
## Create ts for each IP
resolv_df = resolver.pcap_df()
resolv_df_filtered = resolv_df[resolv_df['ip.proto'] == DNS_PROTO]
IPs = resolv_df_filtered['ip.src'].unique()
flows_ip = {}
flows_ts_ip_scoped = {}
flows_ts_ip_total = {}
infra_ip = ['172.20.0.11', '172.20.0.12', '192.168.150.10', '172.20.0.10']
first_pass = resolv_df_filtered[((~resolv_df_filtered['ip.src'].isin(infra_ip)))  \
                                         & (resolv_df_filtered['dns.qry.name'] == evil_domain)]
solo = solo_pipeline(first_pass)

# Add all scope data to IPs found in resolver address space
# This should be a valid topo sorted list of the scopes (it will be proccessed in order)
scopes = [resolver, root, tld, sld]
cache_window = window # see above 
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
#         print(scope)
        # Find matches
        matches = scope.search(ip, flows_ip[ip])
        
        # Update df for ip
        combined_scope = combineScopes(matches)
        combined_scope = scope_label(combined_scope, scope.name)
        combined_scope["scope_name"]=scope.name
        flows_ip[ip] =combineScopes([flows_ip[ip],combined_scope])
        
        # update ts for ip
        new_ts_matches = scopeToTS(combined_scope)
#         print(combined_scope)
#         print(new_ts_matches)
        if len(new_ts_matches) == 0:
            continue
        new_ts_matches["scope_name"]=scope.name
        flows_ts_ip_scoped[ip] = combineScopes([flows_ts_ip_scoped[ip], new_ts_matches])
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
        
        # label scope col as category
        flows_ip[ip]["scope_name"] = flows_ip[ip]["scope_name"].astype('category')
        flows_ts_ip_scoped[ip]["scope_name"] = flows_ts_ip_scoped[ip]["scope_name"].astype('category')
        
        # remove nans with 0
        flows_ip[ip].fillna(0, inplace=True)
        flows_ts_ip_scoped[ip].fillna(0, inplace=True)
        flows_ts_ip_total[ip].fillna(0, inplace=True)


# In[ ]:


flows_ip[ip]['dns.qry.name'].unique()


# In[ ]:


flows_ip[ip]


# In[ ]:


flows_ts_ip_total[ip]


# In[ ]:


# extract scope order
flows_ip[ip]["scope_name"].cat.codes


# In[ ]:


## Viz
# importing Libraries
  
# import pandas as pd
import pandas as pd
  
# importing matplotlib module
import matplotlib.pyplot as plt
plt.style.use('default')
  
# %matplotlib inline: only draw static
# images in the notebook
# get_ipython().run_line_magic('matplotlib', 'inline')


# In[ ]:


# code
# Visualizing The Open Price of all the stocks
  
# to set the plot size
plt.figure(figsize=(16, 8), dpi=150)
  
# using plot method to plot open prices.
# in plot method we set the label and color of the curve.

for f in flows_ts_ip_total:
    flows_ts_ip_total[f]['count'].plot(label=f)
  
plt.title('Requests per second')
  
# adding Label to the x-axis
plt.xlabel('Time')
plt.ylabel('Requests (seconds)')
  
# adding legend to the curve
plt.legend()


# In[ ]:


# get_ipython().system('pip install scikit-learn')
import numpy as np


# In[ ]:


import math
def ip_to_group(ip):
    if ip.split(".")[0] != '102':
        return -1
    return math.floor((int(ip.split(".")[-1])-2) / 5)
def get_real_label(dic):
    data = dic.keys()
    result = np.array([ip_to_group(xi) for xi in data])
    return result


# In[ ]:


answers = get_real_label(flows_ts_ip_total)


# In[ ]:


from sklearn import metrics
from statistics import mean
from sklearn.metrics import confusion_matrix

# compute cluster purity
def purity_score(y_true, y_pred):
    # compute contingency matrix (also called confusion matrix)
    contingency_matrix = metrics.cluster.contingency_matrix(y_true, y_pred)
    # return purity
    return np.sum(np.amax(contingency_matrix, axis=0)) / np.sum(contingency_matrix) 

def weighted_purity(true_labels, found_labels):
    s = 0
    total = 0
    for c in true_labels.unique():
        selection = df[df['cluster'] == c]
        p = purity_score(selection['real_label'], selection['cluster'])
        total += len(selection)
        s += p * len(selection)
    return s/total

from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score, fowlkes_mallows_score, homogeneity_completeness_v_measure
def gpt_cluster_metrics(true_labels, found_labels):

    # Calculate the Adjusted Rand Index
    ari = adjusted_rand_score(true_labels, found_labels)
    ari_range = (-1, 1)
    ari_ideal = 1

    # Calculate the Normalized Mutual Information
    nmi = normalized_mutual_info_score(true_labels, found_labels)
    nmi_range = (0, 1)
    nmi_ideal = 1

    # Calculate the Fowlkes-Mallows Index
    fmi = fowlkes_mallows_score(true_labels, found_labels)
    fmi_range = (0, 1)
    fmi_ideal = 1

    # Calculate homogeneity, completeness, and V-measure
    homogeneity, completeness, v_measure = homogeneity_completeness_v_measure(true_labels, found_labels)
    hcv_range = (0, 1)
    hcv_ideal = 1

    # Print the results
    print(f"Adjusted Rand Index: {ari:.4f} [range: {ari_range}, ideal: {ari_ideal}]")
    print(f"Normalized Mutual Information: {nmi:.4f} [range: {nmi_range}, ideal: {nmi_ideal}]")
    print(f"Fowlkes-Mallows Index: {fmi:.4f} [range: {fmi_range}, ideal: {fmi_ideal}]")
    print(f"Homogeneity: {homogeneity:.4f} [range: {hcv_range}, ideal: {hcv_ideal}]")
    print(f"Completeness: {completeness:.4f} [range: {hcv_range}, ideal: {hcv_ideal}]")
    print(f"V-measure: {v_measure:.4f} [range: {hcv_range}, ideal: {hcv_ideal}]")


# In[ ]:


#!pip install fastdtw
from fastdtw import fastdtw
def my_dist(ts1, ts2):
    distance, path = fastdtw(ts1, ts2)
    return distance



from scipy.spatial.distance import pdist
def calc_dist_matrix(samples, my_dist):
    # create a list of dataframe values
#     print(samples)
    X = [df.values.flatten() for df in samples.values()]
    n_samples = len(X)
    dist_mat = np.zeros((n_samples, n_samples))
    for i in range(n_samples):
        for j in range(i+1, n_samples):
            d = my_dist(X[i], X[j])
            dist_mat[i, j] = d
            dist_mat[j, i] = d
    return squareform(dist_mat)


def cast_col(col: pd.Series) -> pd.Series:
    if col.dtype == 'object':
        if all([is_float(x) for x in col]):
            return col.astype(float)
        elif all([is_int(x) for x in col]):
            return col.astype(int)
        elif all([is_date(x) for x in col]):
            return pd.Series(pd.to_datetime(col)).astype(int)
        else:
            return col.astype(str)
    elif np.issubdtype(col.dtype, np.datetime64):
        return pd.Series(col.astype(np.int64))
    else:
        return col


def is_float(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False


def is_int(s: str) -> bool:
    try:
        int(s)
        return True
    except ValueError:
        return False


def is_date(s: str) -> bool:
    try:
        pd.to_datetime(s)
        return True
    except ValueError:
        return False


def cast_columns(df):
    for col in df.columns:
        df[col] = cast_col(df[col])
    return df
 #    for col in df.columns:
  #       if df[col].dtype != float:
   #          try:
    #             df[col] = df[col].astype(float)
     #        except ValueError:
      #           df[col] = df[col].astype(str)
       #      except TypeError:
        #         df[col] = df[col].astype(str)
    #return df

from scipy.cluster.hierarchy import dendrogram, linkage
from scipy.cluster.hierarchy import fcluster
from sklearn.metrics import silhouette_score
from scipy.spatial.distance import squareform


def cluster(samples, max_clust, display=False):
    dist_mat = calc_dist_matrix(samples, my_dist)

    # Perform hierarchical clustering using the computed distances
    Z = linkage(dist_mat, method='single')

    # Plot a dendrogram to visualize the clustering
    if display:
        dendrogram(Z)

    # Extract the cluster assignments using the threshold
    labels = fcluster(Z, max_clust, criterion='maxclust')
#     print(labels)

    return labels


def evaluate(df_dict, features, display=False):
    data = {key: df.loc[:, features] for key, df in df_dict.items()}
    for ip in data:
        data[ip] = data[ip][list(features)]
#     print(answers)
    max_clust = len(np.unique(answers))
    return purity_score(answers, cluster(data, max_clust, display))


# In[ ]:


purity = evaluate(flows_ts_ip_total, ['frame.time'], display=True)
print("Average purity: " + str(purity))


# In[ ]:


# Find best features
import itertools
from tqdm import tqdm
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor
import os


def findsubsets(s, n):
    return list(itertools.combinations(s, n))


def evaluate_subset(df, subset):
    score = evaluate(df, subset)
    return score, subset


def iterate_features(df, n, filename):
    features = df[next(iter(df))].columns
    subsets = findsubsets(features, n)
    results = []
    num_cpus = os.cpu_count() * 2
    print("Using " + str(num_cpus) + " cpus for " + str(len(subsets)) + " subsets")
    with mp.Pool(processes=num_cpus) as pool:
        results = []
        for subset in subsets:
            results.append(pool.apply_async(evaluate_subset, args=(df, subset)))
        with open(filename, 'a') as f:
            for result in tqdm(results, total=len(subsets)):
                score, subset = result.get()
                f.write(str(score) + "\t" + str(subset) + "\n")


flows_ts_ip_total_str_int = {}
for ip in flows_ts_ip_total:
    flows_ts_ip_total_str_int[ip] = cast_columns(flows_ts_ip_total[ip])

for n in range(1, 4):
    best_features = iterate_features(flows_ts_ip_total_str_int, n,
                                     "dtws_dns_all_" + str(n) +
                                     "_" + str(datetime.now()) + ".output")


# In[ ]:
