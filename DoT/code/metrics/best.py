import json

with open('input.json') as f:
    d = json.load(f)

output = {}
for experiment, data in d.items():
    best = {}
    output[experiment] = {}
    for features in data:
        for m in features.values():
            # print(m)
            scope = m[0]['scope']
            recall_at_1 = m[0]['1'][0]['recall']
            if scope not in best or best[scope] < recall_at_1:
                best[scope] = recall_at_1
                output[experiment][scope] = m
print(json.dumps(output))
