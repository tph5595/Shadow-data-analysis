#!/usr/bin/env python
# coding: utf-8

from datetime import datetime
import pandas as pd
import os

import numpy as np
import math
import statsmodels.api as sm


def cast_col(col: pd.Series) -> pd.Series:
    if col.dtype == 'object':
        if all([is_float(x) for x in col]):
            return col.astype(float)
        elif all([is_int(x) for x in col]):
            return col.astype(float)
        elif all([is_date(x) for x in col]):
            return pd.Series(pd.to_datetime(col)).astype(float)
        else:
            return col.astype(str)
    elif np.issubdtype(col.dtype, np.datetime64):
        return col.astype(np.int64)
    else:
        return col.astype(float)


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


def get_chat_logs(scope):
    df = scope.as_df()
    df["text_len"] = df["text"].apply(len)
    users = df["username"].unique()
    client_log = {}
    for user in users:
        client_log[user] = df_to_ts(df[df["username"] == user], time_col='time').set_index('time')
    return client_log


client_chat_logs = get_chat_logs(chatlog)


def ip_to_user(ip, group_size=5, starting=10):
    local_net = int(ip.split(".")[-1]) - starting
    user = local_net % group_size
    group = math.floor(local_net/group_size)
    return '/tordata/config/group_' + str(group) + "_user_" + str(user)


# https://www.datainsightonline.com/post/cross-correlation-with-two-time-series-in-python
# from scipy import signal

def ccf_values(series1, series2):
    p = series1
    q = series2
    p = (p - np.mean(p)) / (np.std(p) * len(p))
    q = (q - np.mean(q)) / (np.std(q))
    c = np.correlate(p, q, 'full')
    return c


def ccf_plot(lags, ccf):
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.plot(lags, ccf)
    ax.axhline(-2/np.sqrt(23), color='red', label='5% \
    confidence interval')
    ax.axhline(2/np.sqrt(23), color='red')
    ax.axvline(x=0, color='black', lw=1)
    ax.axhline(y=0, color='black', lw=1)
    ax.axhline(y=np.max(ccf), color='blue', lw=1,
               linestyle='--', label='highest +/- correlation')
    ax.axhline(y=np.min(ccf), color='blue', lw=1,
               linestyle='--')
    ax.set(ylim=[-1, 1])
    ax.set_title('Cross Correlation', weight='bold', fontsize=15)
    ax.set_ylabel('Correlation Coefficients', weight='bold',
                  fontsize=12)
    ax.set_xlabel('Time Lags', weight='bold', fontsize=12)
    plt.legend()


def ccf_calc(sig1, sig2):
    corr = sm.tsa.stattools.ccf(sig2, sig1, adjusted=False)

    # Remove padding and reverse the order
    return corr[0:(len(sig2)+1)][::-1]


def cross_cor(ts1, ts2, debug=False, max_offset=300, only_positive=True):
    # ensure format is correct (only keep first col
    # ts1_values = ts1['count'] # ts1.iloc[:,0]
    # ts2_values = ts2['count'] # ts2.iloc[:,0]

    # Calculate values
    # print(ts1)
    ccf = ccf_calc(ts1, ts2)
    # lags = signal.correlation_lags(len(ts1_values), len(ts2_values))

    # keep only positive lag values
    # Not needed with stats packate
    # if only_positive:
    #     ccf = ccf[lags >= 0]
    #     lags = lags[lags >= 0]

    # ccf = ccf[:min(len(ccf), max_offset)]

    # find best
    best_cor = max(ccf)
    best_lag = np.argmax(ccf)

    if debug:
        print('best cross correlation: ' + str(best_cor) + " at time lag: " + str(best_lag))
        print(len(ccf))
        print(ccf)
        ccf_plot(range(len(ccf)), ccf)
    # print(ccf)
    # assert best_cor >= -1 and best_cor <= 1
    return best_cor, best_lag


def compare_ts(ts1, ts2, debug=False):
    # dtw_classic, path_classic = dtw(ts1, ts2, dist='square',
    #                             method='classic', return_path=True)
    # return dtw_classic
    # print(ts1)
    # print(ts2)
    # dist, lag = cross_cor(pd.Series(ts1), pd.Series(ts2))
    dist, lag = cross_cor(ts1, ts2, debug=debug)
    # assert dist >= -1 and dist <= 1
    dist = dist * -1  # flip for use as distance metric
    # assert dist >= -1 and dist <= 1
    return dist, lag


def normalize_ts(ts):
    ts = (ts-ts.min())/(ts.max()-ts.min())
    return ts.fillna(0)


def compare_ts_reshape(ts1, ts2, debug=False):
    # buffer_room = 120  # in seconds
    range = min(ts2.index.values), max(ts2.index.values)
    ts1 = ts1.loc[(ts1.index >= range[0]) & (ts1.index <= range[1])]
    # ts1 = ts1[(ts1['frame.time'] >= int(range[0])) &
    #           (ts1['frame.time'] <= int(range[1]))]
    ts1 = ts1.loc[:, 'tda_pl']

    ts1_norm = np.array(ts1.copy())
    ts2_norm = np.array(ts2.copy())

    # delay = 0

    # ts1_norm.index = ts1_norm.index + pd.DateOffset(seconds=delay)

    # lock to same range with buffer room
    # on each side to account for network (or PPT) delay

    # detect if no overlap
    if len(ts1_norm) < 2 or len(ts2_norm) < 2:
        return float("inf"), 0

    # Normalize peaks?
    # ts1_norm = normalize_ts(ts1_norm)
    # ts2_norm = normalize_ts(ts2_norm)

    # plot_ts(ts1_norm, ts2_norm)
    # exit(1)

    # else:
    #     ts1_norm = ts1_norm.tolist()
    #     ts2_norm = ts2_norm.tolist()

    score, lag = compare_ts(ts1_norm, ts2_norm, debug=debug)

    return score, lag


def plot_ts(ts1, ts2):
    # to set the plot size
    plt.figure(figsize=(16, 8), dpi=150)

    # normalize_ts(ts1['count']).plot(label='ts1')
    # normalize_ts(ts2['count']).plot(label='ts2')
    ts1['count'].plot(label='ts1')
    ts2['count'].plot(label='ts2')

    plt.title('Requests per second')

    # adding Label to the x-axis
    plt.xlabel('Time')
    plt.ylabel('Requests (seconds)')

    # adding legend to the curve
    plt.legend()
plot_ts(client_chat_logs['/tordata/config/group_0_user_0'], flows_ts_ip_total['102.0.0.10'])


# In[ ]:


# from scipy.cluster.hierarchy import dendrogram, linkage
# from scipy.cluster.hierarchy import fcluster
from sklearn.metrics import silhouette_score
from scipy.spatial.distance import squareform


# def cluster(samples, max_clust, display=False, multi_to_single=lambda x: x):
#     dist_mat = calc_dist_matrix(samples,
#                                 my_dist,
#                                 multi_to_single=multi_to_single)

#     # Perform hierarchical clustering using the computed distances
#     Z = linkage(dist_mat, method='single')

#     # Plot a dendrogram to visualize the clustering
#     if display:
#         dendrogram(Z)

#     # Extract the cluster assignments using the threshold
#     labels = fcluster(Z, max_clust, criterion='maxclust')
# #     print(labels)

#     return labels


def evaluate(src_raw, dst_raw, src_features, dst_feaures, display=False, params=TDA_Parameters(0, 3, 1, 1, 1)):
    src = {}
    dst = {}
    for ip in src_raw:
        src[ip] = ts_to_tda(src_raw[ip][src_features].copy(deep=True), params=tda_config)
    for user in dst_raw:
        dst[user] = ts_to_tda(dst_raw[user][dst_feaures].copy(deep=True), params=tda_config)
    correct = 0.0
    for user in dst:
        best_score = 0
        best_ip = 0
        for ip in src:
            score, _ = compare_ts_reshape(src[ip].copy(deep=True), dst[user].copy(deep=True))
            if score < best_score:
                best_score = score
                best_ip = ip
        if user == ip_to_user(best_ip):
            correct += 1
    accuracy = correct / len(src)
    return accuracy
# Find best features
import itertools
from tqdm import tqdm
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor
import os


def findsubsets(s, n):
    return list(itertools.combinations(s, n))


def evaluate_subset(src_df, dst_df, src_features, dst_feaures, tda_config=None):
    try:
        score = evaluate(src_df, dst_df, list(src_features), list(dst_feaures), params=tda_config)
    except: 
        score = -1
    return score, src_features


def iterate_features(src_df, dst_df, n, dst_features, tda_config, filename):
    features = src_df[next(iter(src_df))].columns
    subsets = findsubsets(features, n)
    results = []
    num_cpus = int(os.cpu_count())
    print("Using " + str(num_cpus) + " cpus for " + str(len(subsets)) + " subsets")
    with mp.Pool(processes=num_cpus) as pool:
        results = []
        for subset in subsets:
            results.append(pool.apply_async(evaluate_subset, args=(src_df, dst_df, subset, dst_features, tda_config)))
        with open(filename, 'a') as f:
            for result in tqdm(results, total=len(subsets)):
                score, subset = result.get()
                out = str(score) + "\t" + str(subset) + "\n"
                f.write(out)


flows_ts_ip_total_str_int = {}
for ip in flows_ts_ip_total:
    flows_ts_ip_total_str_int[ip] = cast_columns(flows_ts_ip_total[ip])

chat_log = {}
for user in client_chat_logs:
    chat_log[user] = cast_columns(client_chat_logs[user])

src_df = flows_ts_ip_total_str_int
dst_df = chat_log

dst_df_count = {}
for user in dst_df:
    dst_df_count[user] = dst_df[user]['count']

single_user = '/tordata/config/group_0_user_0'
single_ip = '102.0.0.10'
dst_single = {single_user: dst_df_count[single_user]}
src_single = {single_ip: flows_ts_ip_total[single_ip]}
# plot_ts(client_chat_logs['/tordata/config/group_0_user_0'],
#                           flows_ts_ip_total['102.0.0.10'])

# purity = evaluate(src_single, dst_single, ['count'], display=True)
# purity = evaluate(src_df, dst_df_count, ['count'], display=True)
# print("Accuracy: " + str(purity*100) + "%")


def evaluate_tda(src_df, dst_df, tda_params):
    try:
        dst_arr = {}
        for ip in dst_df:
            dst_arr[ip] = np.array(
                    ts_to_tda(
                        dst_df[ip].loc[:, features],
                        tda_params))
        assert dst_arr[single_user].ndim == 1
        result = evaluate(src_df, dst_arr, ['count'], display=True, params=tda_params)
    except Exception:
        result = -1
    return result, tda_params.thresh




# In[29]:


def eval_model(src_raw, dst_raw, src_features, dst_feaures):
    src = {}
    dst = {}
    for ip in src_raw:
        src[ip] = ts_to_tda(src_raw[ip][src_features].copy(deep=True), params=tda_config)
    for user in dst_raw:
        dst[user] = ts_to_tda(dst_raw[user][dst_feaures].copy(deep=True), params=tda_config)
    correct = 0.0
    for user in tqdm(dst):
        best_score = 0
        best_ip = 0
        for ip in src:
            score, _ = compare_ts_reshape(src[ip].copy(deep=True), dst[user].copy(deep=True))
            if score < best_score:
                best_score = score
                best_ip = ip
        if user == ip_to_user(best_ip):
            correct += 1
    accuracy = correct / len(src)
    return accuracy


# In[ ]:


num_cpus = os.cpu_count()
skip = 1
dim = 0
window = 3
k = 9
thresh = float("inf")
tda_config = TDA_Parameters(dim, window, skip, k, thresh)

src_df = flows_ts_ip_total
dst_df = client_chat_logs

for output_size in range(1, len(dst_df)+1):
    for n in range(1, 3):
        for features in findsubsets(dst_df[next(iter(dst_df))].columns, output_size):
#             dst_arr = {}
#             for ip in dst_df:
#                 dst_arr[ip] = ts_to_tda(dst_df[ip].loc[:, features], params=tda_config)
#             assert dst_arr[single_user].ndim == 2
            best_features = iterate_features(src_df, dst_df, n, features, tda_config,
                                             "post_tor_chatlog_tda_match_dns_all_" + str(n) +
                                             "_outputFeatures_" + str(features) +
                                             "_" + str(datetime.now()) +
                                             ".output")


# In[4]:


# for n in range(2,3):
#     best_features = iterate_features(src_df, dst_df, n,
#                                      "chatlog_dtw_dns_all_" + str(n) +
#                                      "_" + str(datetime.now()) + ".output")


# In[5]:


ts1 = flows_ts_ip_total['102.0.0.107'][['count']]
ts2 = client_chat_logs['/tordata/config/group_19_user_2'][['count']]
ts1 = ts_to_tda(ts1, params=tda_config)
ts2 = ts_to_tda(ts2, params=tda_config)
compare_ts_reshape(ts1, ts2, debug=True)


# In[17]:


eval_model(flows_ts_ip_total, client_chat_logs, ['count'], ['count'])


# In[7]:


ip_to_user(best_ip)


# In[8]:


# plot_ts(client_chat_logs['/tordata/config/group_0_user_2'], flows_ts_ip_total['102.0.0.99'])


# In[9]:


# client_chat_logs['/tordata/config/group_0_user_2']

