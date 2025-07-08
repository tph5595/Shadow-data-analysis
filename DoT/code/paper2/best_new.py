#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
import yaml


# In[2]:


config_file = "../config_multiscope/doh_vpn_multi_scale5k10k.yaml"
with open(config_file, 'r') as file:
    config = yaml.safe_load(file)


# In[3]:


df = pd.read_csv(config_file + '.csv')


# In[10]:


#df.sort_values(by='Accuracy', ascending=False).head(50)


# In[4]:


scopes = [s[1] for s in config['scope_config']]
scopes


# In[5]:


def extract_scope(x):
    if x[-1] not in scopes:
        return 'global'
    return x[-1]
df['Scope'] = df['src_feature'].str.split('_').apply(extract_scope)
scopes_seen = set(df['Scope'].to_list())


# In[6]:


best = {}

for i, r in df.iterrows():
    s = r['Scope']
    if s not in best or r['Accuracy'] > best[s]['Accuracy']:
        best[s] = r


# In[12]:


best_df = pd.DataFrame.from_dict(best, orient='index')
best_df.to_csv(config_file + 'best.csv', index=False)
best_df


# In[ ]:




