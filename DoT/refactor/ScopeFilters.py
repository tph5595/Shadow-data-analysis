UDP_PROTO = 17
DNS_PORT = 53
DOT_PORT = 853
DOH_PORT = 443
HTTP_PORT = 80
TCP_PROTO = 6


def getPossibleIPs(scopes):
    resolver = [scope for scope in scopes if "resolver" in scope.name.lower()]
    assert len(resolver) == 1
    resolver = resolver[0]
    resolv_df = resolver.as_df()
    resolv_df_filtered = resolv_df[resolv_df['tcp.dstport'] == DOH_PORT]
    return resolv_df_filtered['ip.src'].unique()


def dns_filter(df, evil_domain):
    if ('dns.qry.name' in df.columns and 'tcp.dstport' in df.columns):
        return df[(df['dns.qry.name'] == evil_domain)
                  | (df['dns.qry.name'].isna())
                  & (df['tcp.dstport'] == DOT_PORT)]
    else:
        return df[(df['dns.qry.name'] == evil_domain)
                  | (df['dns.qry.name'].isna())]


def dot_filter(df, evil_domain):
    # for dot, we check if tcp port is 853, we cannot check for dns.qry.name in
    # this case if it is upstream DNS, i.e for eg. from resolver to root, tld,
    # etc then we cannot check for tcp.dstport because it is udp (Plain DNS)
    # so, we check if either dns.qry.name is evil.dne or tcp.dstport is 853
    print(df)
    if ('dns.qry.name' not in df.columns and 'tcp.dstport' not in df.columns):
        raise Exception("No DNS or TCP port column found")

    if ('dns.qry.name' in df.columns and 'tcp.dstport' not in df.columns):
        print(1)
        return df[(df['dns.qry.name'] == evil_domain)
                  | (df['dns.qry.name'].isna())]

    print(2)
    return df[(df['dns.qry.name'] == evil_domain)
              | (df['dns.qry.name'].isna())
              | (df['tcp.dstport'] == DOT_PORT)
              | (df['tcp.dstport'] == DOH_PORT)
              | (df['udp.dstport'] == DNS_PORT)]


def isp_filter(df, evil_domain):
    # for isp traffic, we filter out DoT and HTTP traffic from the dataframe
    if ('tcp.dstport' not in df.columns):
        raise Exception("No TCP port column found")

    return df[(df['udp.dstport'] == DNS_PORT)
              | (df['tcp.dstport'] == HTTP_PORT)]
