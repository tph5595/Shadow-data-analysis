import yaml
import pickle
import sys




config_file = sys.argv[1]
with open(config_file, 'r') as file:
    config = yaml.safe_load(file)




p_filename = "../" + config['experiment_name'] + "_ts.pkl"

with open(p_filename, 'rb') as file:
    src = pickle.load(file)
    dst = pickle.load(file)




dst['/tordata/config/group_0_user_0']


# In[5]:


# src['102.0.0.10']


# In[6]:


import pandas as pd 

def ts2nccvec(ts: pd.core.frame.DataFrame):
    sample_offset = ((len(ts)-1)**0.5)
    return (ts - ts.mean()) / (ts.std()*sample_offset)

vec = ts2nccvec(dst['/tordata/config/group_0_user_0']["text_len"])
vec


# In[7]:


import numpy as np
np.dot(vec.to_numpy(), vec.to_numpy())


# ### Todo
# - **Find way to align dataset**
#     - chunk, fill zeros, etc
#     - _Last big thing to do before all out test of method_
# - Get end to end working
#     - Send pcaps dfs through ncc GIS stuff
# - Run new experiment loop
#     - run through all features/combos and report metrics

# In[8]:


scale_factor = 300
chunk_size = td = pd.Timedelta(1, "W")/scale_factor
chunk_size


# In[9]:


start = min([src[ip].index[0] for ip in src])
start


# In[10]:


# Fill zeros in missing indexes
full_index = pd.Index([])

for ip in src:
    full_index = full_index.union(src[ip].index)

for user in dst:
    full_index = full_index.union(dst[user].index)
print(full_index)
for ip in src:
    src[ip] = src[ip].reindex(full_index, fill_value=0)
    assert len(src[ip]) == len(full_index)

for user in dst:
    dst[user] = dst[user].reindex(full_index, fill_value=0)
    assert len(dst[user]) == len(full_index)


# In[11]:


src_chunks = {}

for ip in src:
    cur = start
    end = src[ip].index[-1]
    src_chunks[ip] = {}

    while cur < end:
        src_chunks[ip][cur] = src[ip][cur:cur+chunk_size]
        cur += chunk_size

dst_chunks = {}

for user in dst:
    cur = start
    end = dst[user].index[-1]
    dst_chunks[user] = {}

    while cur < end:
        dst_chunks[user][cur] = dst[user][cur:cur+chunk_size]
        cur += chunk_size


# In[12]:


# - fill out zeros in the other timestamps for smaller chunks (could do this before or after chunking)
# - copy NCCTree class over
# - Send through as test (def eval(src_chunks[f], dst_chunks[f], label_func) -> List[Metrics] )
# - Setup experiment full loop (loop over all feature combos and multithread, save out to a file)


# In[13]:


#dst_chunks['/tordata/config/group_0_user_0'][pd.Timestamp('2025-05-07 11:02:22.692000')]


# In[14]:


def eval_model(src, src_feature, dst, dst_feature, label_func, metric_func) -> {str: float}:
    output = model(src, src_feature, dst, dst_feature)
    labels = label_func(src_chunks)
    return metric_func(output, labels)


# In[15]:


import math
def ip_to_user_multi(ip, group_size=5, starting=10):
    num_isps = 10
    isp = int(int(ip.split(".")[-2]))
    node_number = (int(ip.split(".")[-1]) - starting )*num_isps + isp
    user = node_number % group_size
    group = math.floor(node_number / group_size)
    return '/tordata/config/group_' + str(group) + "_user_" + str(user)

def label_f(d) -> {str: str}:
    result = {}
    for k in d:
        result[k] = ip_to_user_multi(k)
    return result

print(src.keys())
print(ip_to_user_multi('102.0.8.13'))


# In[16]:


#from functools import lru_cache

#@lru_cache(maxsize=None) 
def metric_match(x, y, yi):
    return  x == y[yi][0]

#@lru_cache(maxsize=None) 
def accuracy(output, labels) -> float:
    if len(output) == 0:
        return 0.
    correct = 0.0
    for x in output:
        if metric_match(labels[x], output[x], 0):
            correct += 1.
    accuracy = correct/len(output)
    return accuracy

#@lru_cache(maxsize=None) 
def rank(output, labels) -> [float]:
    result = [0.]*len(output)

    for idx, x in enumerate(output):
        for yi in range(len(output[x])):
            if metric_match(labels[x], output[x], yi):
                result[idx] = yi + 1
                break
        if result[idx] == 0:
            print(x)
        #assert result[idx] != 0

    return result

#@lru_cache(maxsize=None) 
def recall_k_f(k):
    def recall_k(output, labels) -> float:
        ranks = rank(output, labels)
        # Must remove values that are 0. These are values that could not be found
        ranks = filter(lambda x: x != 0., ranks)
        return sum([1. if r <= k else 0. for r in ranks])/len(output)
    return recall_k

#@lru_cache(maxsize=None) 
def precision_k_f(k):  
    def precision_k(output, labels) -> float:
        return recall_k_f(k)(output, labels) / float(k)
    return precision_k

#@lru_cache(maxsize=None) 
def f_beta_k_f(k, beta=1.):  
    def f_beta_k(output, labels) -> float:
        recall = recall_k_f(k)(output, labels)
        precision = precision_k_f(k)(output, labels)
        top = (1. + beta * beta) * recall * precision 
        bottom = (beta * beta * precision) + recall
        if bottom == 0:
            return 0
        return top / bottom
    return f_beta_k

#@lru_cache(maxsize=None) 
def MRR(output, labels) -> float:
    ranks = rank(output, labels)
    # Must remove values that are 0. These are values that could not be found
    ranks = filter(lambda x: x != 0., ranks)
    return sum([1./r for r in ranks])/len(output)


# In[17]:


def all_metrics(output, labels):
    metrics = [
        ("Accuracy", accuracy),

        ("Recall@1", recall_k_f(1)),
        ("Recall@2", recall_k_f(2)),
        ("Recall@4", recall_k_f(4)),
        ("Recall@8", recall_k_f(8)),

        ("Precision@1", precision_k_f(1)),
        ("Precision@2", precision_k_f(2)),
        ("Precision@4", precision_k_f(4)),
        ("Precision@8", precision_k_f(8)),

        ("F-beta@1", f_beta_k_f(1)),
        ("F-beta@2", f_beta_k_f(2)),
        ("F-beta@4", f_beta_k_f(4)),
        ("F-beta@8", f_beta_k_f(8)),

        ("MRR", MRR),

        ("Rank", rank)
    ]

    return {m[0]: m[1](output, labels) for m in metrics}

def get_metric_names(m_f):
    return list(m_f({"": [("", 1)]}, {"": ""}).keys())


# In[18]:


import sys
import os
from tqdm import tqdm
sys.path.append("./NCC")
from NCC import NCCTree

def get_ts(p, feature, defualt_size):
    if feature not in p:
        return np.zeros(defualt_size)
    #time = pd.Timestamp('2025-05-07 11:02:22.692000')
    #return p[time][feature].to_numpy()
    return p[feature].to_numpy()

def model(src_chunks, src_feature, dst_chunks, dst_feature, disable_bar=True) -> {str: [(str, float)]}:
    result = {}
    ts_size = len(src_chunks[list(src_chunks.keys())[0]])

    #noise_floor = np.mean([smallest_gt_zero(ts2nccvec(dst[user]['count'])) for user in dst])

    tree = NCCTree(ts_size)
    for p in tqdm(dst_chunks, disable=disable_bar):
        ts = get_ts(dst_chunks[p], dst_feature, ts_size)
        # advoid divide by zero if all zeros 
        #if (ts == 0).all(): continue
        vec = ts2nccvec(ts)
        assert abs(1 - np.linalg.norm(vec)) < 0.001
        tree.insert(vec, p)

    #for _ in range(10):
    for p in tqdm(src_chunks, disable=disable_bar):
        ts = get_ts(src_chunks[p], src_feature, ts_size)
        #if (ts == 0).all(): continue
        vec = ts2nccvec(ts)
        #vec[vec < noise_floor] = 0
        n = tree.ncc(vec, 100)
        #print(ip_to_user_multi(p), n)
        result[p] = n

    # if in and out are set to the same then this confirms it works correctly
    # assert(all(n[i] >= n[i + 1] for i in range(len(n) - 1)))

    return result
#out = model(src, 'count_ISP1-3', dst, 'count')


# In[19]:


# get_ipython().run_cell_magic('time', '', "eval_model(src, 'count', dst, 'count', label_f, all_metrics)\n")


# In[ ]:


def eval_all(src, dst, label_f, metric_f):
    src_features = set([])
    for x in list(src.values()):
        src_features |= set(x.columns)

    dst_features = set([])
    for x in list(dst.values()):
        dst_features |= set(x.columns)
    bad_features = ['frame.time']

    metric_names = get_metric_names(metric_f)

    results = pd.DataFrame(columns=['src_feature', 'dst_feature'] + metric_names)
    for df in dst_features:
        for sf in tqdm(src_features):
            if sf in bad_features: continue
            results.loc[len(results)] = {
                'src_feature': sf, 
                'dst_feature': df,
            } | eval_model(src, sf, dst, df, label_f, metric_f)
    return results

model_all_out = eval_all(src, dst, label_f, all_metrics)
model_all_out


# In[ ]:


model_all_out.to_csv(config_file + '.csv', index=False)
model_all_out.sort_values(by='Accuracy', ascending=False)
