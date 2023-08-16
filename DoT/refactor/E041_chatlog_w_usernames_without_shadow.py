from os.path import isfile, join
import itertools
import multiprocessing as mp
import os
from scipy.spatial.distance import squareform
import heapq
from datetime import datetime
from os import listdir
import pandas as pd
import re
from tqdm import tqdm
import numpy as np
import math
from sklearn import metrics
from sklearn.metrics import (adjusted_rand_score,
                             homogeneity_completeness_v_measure)
from ripser import ripser
from fastdtw import fastdtw
import fast_pl_py
import statsmodels.api as sm

# Local Imports
from PrivacyScope import PrivacyScope
from ScopeFilters import dot_filter, getPossibleIPs
from Solo import Solo
from Packets2TS import Packets2TS
from DFutil import df_to_ts


# ==============================================================================
# Static variables
# ==============================================================================
IP_SEARCH = (True, False)
IP_AND_CACHE_SEARCH = (True, True)
# ==============================================================================
# END Static variables
# ==============================================================================


# ==============================================================================
# Config
# ==============================================================================
DEBUG = False
pcappath = "../doh_data/data/csv/"
logpath = "../doh_data/data/server_log/"
DEFUALT_FILTER = dot_filter
defualt_ip_search = True
window = pd.Timedelta("30 seconds")  # cache size but maybe smaller
# Scopes will be proccessed in order. Ensure order takes path most likely for
# communication
scope_config = [
    # (r".*isp.*.csv", "ISP"),
    (r".*resolver.*", "resolver", DEFUALT_FILTER, IP_SEARCH),
    (r"(.*root).*.csv", "root", DEFUALT_FILTER, IP_AND_CACHE_SEARCH),
    (r"(.*sld).*.csv", "SLD", DEFUALT_FILTER, IP_AND_CACHE_SEARCH),
    (r"(.*tld).*.csv", "TLD", DEFUALT_FILTER, IP_AND_CACHE_SEARCH),
    # (r".*access-service.csv", "Access_service"),
    # (r".*/service.csv", "Service"),
    ]
server_logs = (".*pythonServerThread.stdout", "chatlogs")
# Optional
infra_ip = ['172.20.0.11', '172.20.0.12', '192.168.150.10', '172.20.0.10']
evil_domain = 'evil.dne'
bad_features = ['tcp.srcport', 'udp.srcport', 'tcp.seq',
                'frame.number', 'frame.time_relative', 'frame.time_delta']
# ==============================================================================
# END Config
# ==============================================================================


def getFilenames(path):
    return [path+f for f in listdir(path) if isfile(join(path, f))]


def createScope(data, regex, name, debug=False):
    r = re.compile(regex)
    files = list(filter(r.match, data))
    if debug:
        print("Files for " + name + ": " + str(files))
    return PrivacyScope(files, name)


def createLogScope(logs):
    chatlog = createScope(data, logs[0], logs[1], debug=DEBUG)
    chatlog.time_col = "time"
    chatlog.time_cut_tail = 0
    chatlog.time_format = 'epoch'
    chatlog.as_df()
    return chatlog


# Get data
pcapCSVs = getFilenames(pcappath)
logs = getFilenames(logpath)
data = pcapCSVs + logs
# Setup Input scopes
scopes = [createScope(data, regex, name, debug=DEBUG)
          .set_filter(filter)
          .set_search(search_options)
          for (regex, name, filter, search_options) in scope_config]
# Set up chatlog scopes
chatlog = createLogScope(server_logs)
if DEBUG:
    print("Scopes created")
    print(str(scopes))


ips_seen = getPossibleIPs(scopes)
IPs = list(set(ips_seen) - set(infra_ip))

solo = Solo(window, debug=DEBUG).run(scopes)

# Add all scope data to IPs found in resolver address space
# This should be a valid topo sorted list
# of the scopes (it will be proccessed in order)
for scope in scopes:
    scope.remove_features(bad_features)
    scope.remove_zero_var()


# ADD me here
flows_ts_ip_total = Packets2TS(evil_domain, ignored_ips=[infra_ip + solo])\
                    .run(IPs, scopes)


def ip_to_group(ip):
    if ip.split(".")[0] != '101':
        return -1
    return math.floor((int(ip.split(".")[-1])-2) / 5)


def get_real_label(dic):
    data = dic.keys()
    result = np.array([ip_to_group(xi) for xi in data])
    return result


# compute cluster purity
# def purity_score(y_true, y_pred):
#     # compute contingency matrix (also called confusion matrix)
#     contingency_matrix = metrics.cluster.contingency_matrix(y_true, y_pred)
#     # return purity
#     return np.sum(np.amax(contingency_matrix, axis=0)) / np.sum(contingency_matrix)


# def weighted_purity(true_labels, found_labels):
#     s = 0
#     total = 0
#     for c in true_labels.unique():
#         selection = df[df['cluster'] == c]
#         p = purity_score(selection['real_label'], selection['cluster'])
#         total += len(selection)
#         s += p * len(selection)
#     return s/total


answers = get_real_label(flows_ts_ip_total)


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


def my_dtw(ts1, ts2):
    distance, path = fastdtw(ts1, ts2)
    return distance


def my_dist(ts1, ts2, ip1="", ip2=""):
    return my_pl_ts(ts1, ts2, ip1, ip2)


def rip_ts(window, dim, skip, data, thresh=float("inf")):
    for_pl = {}
    for i in range(0, len(data)-window+1, skip):
        diagrams = ripser(data[i:i+window], maxdim=dim, thresh=thresh)['dgms']
        for_pl[i] = diagrams[dim]
    return for_pl


def tda_trans(pairs, k=2, debug=False):
    pairs = [(x[0], x[1]) for x in pairs]
    return fast_pl_py.pairs_to_l2_norm(pairs, k, debug)


class TDA_Parameters:
    def __init__(self, dim, window, skip, k, thresh):
        self.dim = dim
        self.window = window
        self.skip = skip
        self.k = k
        self.thresh = thresh


def ts_to_tda(data, header="", params=TDA_Parameters(0, 3, 1, 2, float("inf")), debug=False):
    data = data.astype(float)

    # compute birth death pairs
    rip_data = rip_ts(params.window, params.dim, params.skip, data, thresh=params.thresh)
    new_ts = [tda_trans(pairs, params.k, debug) for i, pairs in rip_data.items()]
    return pd.DataFrame({'tda_pl': new_ts}, index=data.index[:len(new_ts)])


def my_pl_ts(ts1, ts2, ip1, ip2):
    return my_dtw(ts1, ts2)


def calc_dist_matrix(samples, my_dist, multi_to_single=lambda x: x):
    # create a list of dataframe values
    X = [multi_to_single(df.to_numpy(), ip) for ip, df in samples.items()]
    n_samples = len(X)
    dist_mat = np.zeros((n_samples, n_samples))
    for i in range(n_samples):
        for j in range(i+1, n_samples):
            d = my_dist(X[i], X[j], i, j)
            dist_mat[i, j] = d
            dist_mat[j, i] = d
    return squareform(dist_mat)


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
        client_log[user] = df_to_ts(df[df["username"] == user]).set_index('time')
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


def ccf_calc(sig1, sig2):
    corr = sm.tsa.stattools.ccf(sig2, sig1, adjusted=False)

    # Remove padding and reverse the order
    return corr[0:(len(sig2)+1)][::-1]


def cross_cor(ts1, ts2, debug=False, max_offset=300, only_positive=True):
    ccf = ccf_calc(ts1, ts2)
    best_cor = max(ccf)
    best_lag = np.argmax(ccf)

    if debug:
        print('best cross correlation: ' + str(best_cor) + " at time lag: " + str(best_lag))
        print(len(ccf))
        print(ccf)
        ccf_plot(range(len(ccf)), ccf)
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
    # print(ts1)
    # ts1 = ts1.loc[:, 'tda_pl']
    ts1 = ts1.values[:, 0]

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


def recall_at_k(heap, k, value):
    """
    Checks if a value is in the top k elements of a heap.

    Args:
        heap (list): Binary heap.
        value: Value to check.
        k (int): Number of top elements to consider.

    Returns:
        bool: True if value is in the top k elements, False otherwise.
    """
    top_k_elements = heapq.nsmallest(k, heap)
    return value in [elem[2] for elem in top_k_elements]


def get_value_position(heap, value):
    """
    Returns the position (index) of a value in a binary heap.

    Args:
        heap (list): Binary heap.
        value: Value to find the position of.

    Returns:
        int: Position (index) of the value in the heap. Returns -1 if the value is not found.
    """
    try:
        position = next(idx for idx, element in enumerate(heap) if element[2] == value)
    except StopIteration:
        position = -1
    return position + 1


def heap_to_ordered_list(heap):
    """
    Converts a binary heap into an ordered list.

    Args:
        heap (list): Binary heap.

    Returns:
        list: Ordered list representing the heap elements.
    """
    ordered_list = []
    while heap:
        ordered_list.append(heapq.heappop(heap))
    return ordered_list


def evaluate(src_raw, dst_raw, src_features, dst_feaures, display=False, params=TDA_Parameters(0, 3, 1, 1, 1)):
    src = {}
    dst = {}
    for ip in src_raw:
        # src[ip] = ts_to_tda(src_raw[ip][src_features].copy(deep=True), params=tda_config)
        src[ip] = src_raw[ip][src_features].copy(deep=True)
    for user in dst_raw:
        # dst[user] = ts_to_tda(dst_raw[user][dst_feaures].copy(deep=True), params=tda_config)
        dst[user] = dst_raw[user][dst_feaures].copy(deep=True)

    correct = 0.0
    rank_list = []
    score_list = []
    recall_2 = 0
    recall_4 = 0
    recall_8 = 0
    rank = 0
    for user in dst:
        best_score = 0
        best_user = 0
        heap = []
        counter = 0
        r2 = False
        r4 = False
        r8 = False
        for ip in src:
            counter += 1
            score, _ = compare_ts_reshape(src[ip].copy(deep=True), dst[user].copy(deep=True))
            if not math.isnan(score) and not math.isinf(score):
                heapq.heappush(heap, (score, counter, ip))
            if score < best_score:
                best_score = score
                best_user = ip_to_user(ip)
        if user == best_user:
            correct += 1
        # print(user)
        if recall_at_k(heap.copy(), 2, user):
            recall_2 += 1
            r2 = True
        if recall_at_k(heap.copy(), 4, user):
            recall_4 += 1
            r4 = True
        if recall_at_k(heap.copy(), 8, user):
            recall_8 += 1
            r8 = True
        if (r2 and (not r4 or not r8)) or (r4 and not r8):
            print("r2: " + str(r2))
            print("r4: " + str(r4))
            print("r8: " + str(r8))
            raise Exception("Bad recall")
        rank += get_value_position(heap, user)
        rank_list += [(get_value_position(heap, user), user)]
        score_list += [(heap_to_ordered_list(heap), user)]
    accuracy = correct / len(src)
    recall_2 = recall_2 / len(src)
    recall_4 = recall_4 / len(src)
    recall_8 = recall_8 / len(src)
    rank = rank / len(src)
    return accuracy, recall_2, recall_4, recall_8, rank, rank_list, score_list


def findsubsets(s, n):
    return list(itertools.combinations(s, n))


def evaluate_subset(src_df, dst_df, src_features, dst_feaures, tda_config=None):
    score = evaluate(src_df, dst_df, list(src_features), list(dst_feaures), params=tda_config)
    return score, src_features


def iterate_features(src_df, dst_df, n, dst_features, tda_config, filename):
    features = src_df[next(iter(src_df))].columns
    subsets = findsubsets(features, n)
    results = []
    num_cpus = int(os.cpu_count()/2)
    print("Using " + str(num_cpus) + " cpus for " + str(len(subsets)) + " subsets")
    with mp.Pool(processes=num_cpus) as pool:
        results = []
        for subset in subsets:
            results.append(pool.apply_async(evaluate_subset, args=(src_df, dst_df, subset, dst_features, tda_config)))
        with open(filename, 'a+') as f:
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


num_cpus = (os.cpu_count() or 1)/2
skip = 1
dim = 0
window = 3
k = 9
thresh = float("inf")
tda_config = TDA_Parameters(dim, window, skip, k, thresh)

src_df = flows_ts_ip_total
dst_df = client_chat_logs

features = ['count']
n = 1
best_features = iterate_features(src_df, dst_df, n, features, tda_config,
                                 "test.out")

# for output_size in range(1, len(dst_df)+1):
#     for n in range(1, 3):
#         for features in findsubsets(dst_df[next(iter(dst_df))].columns, output_size):
#             print("Evaluating " + str(n) + " features from " + str(output_size) + " output features")
#             best_features = iterate_features(src_df, dst_df, n, features, tda_config,
#                                             "with-doh-change-without-shadow_" + "chatlog_all_noTDA_match_dns_all_" + str(n) +
#                                              "_outputFeatures_" + str(features) +
#                                              "_" + str(datetime.now()) +
#                                              ".output")
