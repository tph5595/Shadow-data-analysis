import pandas as pd
import re
from datetime import datetime
import json
import numpy as np
import pickle
from TorCache import Tor_Cache


def no_filter(df, args):
    return df


def _format_epoch(x):
    return datetime.fromtimestamp(float(x))


def _format_time_defualt(x, time_cut_tail, time_format):
    return datetime.strptime(
            x[:time_cut_tail], time_format)


class PrivacyScope:

    def __init__(self, filenames, name):
        self.name = name
        self.filenames = filenames
        self.time_format = '%b %d, %Y %X.%f'
        self.time_cut_tail = -7
        self.time_col = 'frame.time'
        self.filter_func = no_filter
        self.df = None
        self.ip_search_enabled = False
        self.cache_search_enabled = False
        self.cache_timing = pd.Timedelta("300 seconds")

    def __repr__(self):
        return str(self)

    def __str__(self):
        return self.name

    def start_time(self):
        return self.as_df().index.min()

    def set_offset(self, timeoffset):
        self.timeoffset = timeoffset
        self.as_df()
        self.df.index += timeoffset

    def set_index(self, col_name):
        df = self.as_df()
        df.set_index(col_name, inplace=True)
        self.df = df
        return df

    def process_log(self, fn, sep='\t', cols=["time", "format", "data"]):
        df = pd.read_csv(fn, sep=sep, names=cols)
        m = pd.json_normalize(df["data"].apply(json.loads))
        df.drop(["data"], axis=1, inplace=True)
        df = pd.concat([df, m], axis=1, sort=False)
        return df

    def as_df(self, filenames=None):
        if self.df is not None:
            return self.df
        if filenames is None:
            filenames = self.filenames
        df = pd.DataFrame()
        for f in filenames:
            if f.endswith(".csv"):
                ddf = pd.read_csv(f)
            elif f.endswith("stdout"):
                ddf = self.process_log(f)
            df = pd.concat([df, ddf])
        self.df = df
        self.format_time_col()
        return self.df

    def get_ts(self):
        return None

    def format_time_col(self):
        if self.time_format == 'epoch':
            self.df[self.time_col] = \
                    self.df[self.time_col].apply(_format_epoch)
        else:
            self.df[self.time_col] = \
                    self.df[self.time_col].apply(_format_time_defualt,
                                                 args=(self.time_cut_tail,
                                                       self.time_format))
        return self.df

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
        return df[((df['ip.dst'] == ip) |
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

    def remove_zero_var(self, cutoff=0.01):
        df = self.as_df()

        numeric_cols = df.select_dtypes(include=np.number)
        cols_to_drop = numeric_cols.columns[(numeric_cols.std() <= cutoff) |
                                            (numeric_cols.std().isna())]\
                                                    .tolist()
        df_filtered = df.drop(cols_to_drop, axis=1)
        self.df = df_filtered

    def remove_features(self, bad_features):
        df = self.as_df()
        df.drop(bad_features, inplace=True, axis=1)
        self.df = df

    def _map_row(self, row, ip_map, cache):
        ip = row['ip.src']
        five_tuple = (ip,
                      row['ip.dst'],
                      row['tcp.srcport'],
                      row['tcp.dstport'],
                      row['ip.proto'])
        new_ip = ip_map.get(ip, row[self.time_col])

        new_connection = row['tcp.connection.syn']
        if new_connection:
            cache.add(five_tuple, new_ip)
        return cache.get_or_add(five_tuple, new_ip) or ip

    def ip_map(self, src_map, dst_map):
        df = self.as_df()
        five_tuple_cache = Tor_Cache()
        df['ip.src'] = df.apply(self._map_row,
                                args=(src_map, five_tuple_cache),
                                axis=1)
        df['ip.dst'] = df.apply(self._map_row,
                                args=(dst_map, five_tuple_cache),
                                axis=1)
        self.df = df

    def adjust_time_scale(self, offset, scale):
        df = self.as_df()
        df[self.time_col] = df[self.time_col].apply(lambda x:
                                                    int(x.timestamp()))
        df[self.time_col] = (df[self.time_col] - offset) * scale + offset
        col = df[self.time_col]
        self.df = df
        self.time_format = 'epoch'
        self.format_time_col()
        self.df = self.df.set_index(self.time_col)
        self.df[self.time_col] = col


def save_scopes(scopes, ending=""):
    for scope in scopes:
        with open(scope.name + ending + '.pickle', 'wb') as file:
            pickle.dump(scope, file)


def load_scopes(scope_names, ending=""):
    return [pickle.load(open(name + ending + ".pickle", 'rb'))
            for name in scope_names]
