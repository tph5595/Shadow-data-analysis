import json

with open('output/input.json') as f:
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

with open('output/best.json', 'w') as f:
    json.dump(output, f)

print('Finding Best F1')
# format for graph needs
for experiment, data in output.items():
    with open("output/{}-f1.csv".format(experiment[2:]), "w") as f:
        f.write("Missing title\n")
        for scope, data in data.items():
            f.write("{},{},{},{},{}\n".format(
                data[0]['1'][2]['f1'],
                data[0]['2'][2]['f1'],
                data[0]['4'][2]['f1'],
                data[0]['8'][2]['f1'],
                scope
                ))

print('Finding Best MRR')
for experiment, data in output.items():
    with open("output/{}-mrr.csv".format(experiment[2:]), "w") as f:
        f.write("Missing title\n")
        for scope, data in data.items():
            f.write("{},{}\n".format(
                data[0]['1'][3]['mrr'],
                scope
                ))
