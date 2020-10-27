import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import json
import csv

df = pd.read_csv("office_beacons_interaction.csv")

count = {}

for index, row in df.iterrows():

    if row[2] not in count:
        count[row[2]] = [row[1]]

    elif row[2] in count and row[1] not in count[row[2]]:
        count[row[2]].append(row[1])

m = ['0','1','2','3','4','5','6','7','8','9']
plot = [0] * len(m)

for key in count:
    count[key] = len(count[key])
    plot[count[key]] += 1

fig = plt.figure()
y_pos = np.arange(len(m))

plt.bar(y_pos, plot, align='center', alpha=0.5)
plt.xticks(y_pos, m)
plt.title('Contact Distribution')
plt.xlabel("Number of Close Interactions")
plt.ylabel("Number of People")

plt.show()

with open('office.json', 'w') as file:
    for key, value in count.items():
        file.write("%s %s\n" % (key,value)) 
    
    #file.write(json.dumps(count))

