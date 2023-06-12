# Shadow-data-analysis
ALL DATA AND EXPERIMENT CODE EXISTS ON THE BRANCHES OF THIS REPO
## Ideas
- Cluster dns requests to find groups
- Some how to encode frequency of different signals or ordering of different indicators ( relative to other signals, i.e. I will see a DNS then up to 1 hour of internet traffic )
- model to do the above? automatically determine those relationships
- Then have a model to take the knowledge of above and build candadite flows with certain accuracies
- generate potential flows in such a way as to only include those that could be related to the indicator in question (group chat logs, server access, tweet post, etc.)
- Take these flows and embed them into a metric space 
- Plot this with UMAP to see if there is any structure, a clear cluster with noise (unrelated users)
- cluster in this space
- If no clusters exist, idk
-
- quantify how this changes when we monitor for longer
- develop countermeasures 
- compute theoritical best privacy tool's attributes
- deanon users of a group
-
- find group then users
- Do we find groups then deanon users or other way around?
-
- find min needed to identify groups, can we with just web access scope, just dns, tor access, etc. i.e. can you with just one scope and post knowledge (tweet post that is)

- Two paths: 
  - find flows that were happening to the site at the same time as a post/find users with similar access patterns
  - or 
  - Find group based on minimum scope then find flows for each of group with minimum need to deanon
  - I think this is the same thind, second one is a better description
