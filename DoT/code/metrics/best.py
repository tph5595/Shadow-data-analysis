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

with open('best.json', 'w') as f:
    json.dump(output, f)

# format for graph needs
for experiment, data in output.items():
    with open("{}.csv".format(experiment), "w") as f:
        f.write("Missing title")
        for scope, data in data.items():
            f.write("{},{},{},{},{}".format(
                data[0]['1'][2]['f1'],
                data[0]['2'][2]['f1'],
                data[0]['4'][2]['f1'],
                data[0]['8'][2]['f1'],
                scope
                ))
