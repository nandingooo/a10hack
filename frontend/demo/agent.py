"""Two fixed-purpose agents. All fixture access goes through the gateway RPC."""
import csv
import io
import json
import sys
import time


def request(action, target, detail=""):
    print(json.dumps(dict(action=action, target=target, detail=detail)), flush=True)
    reply = json.loads(input())
    if reply["verdict"] == "STOP":
        sys.exit(0)
    time.sleep(0.8)
    return reply


def analyze():
    raw = request("read", "iris.csv")["content"]
    rows = list(csv.reader(io.StringIO(raw)))
    species = rows[0][2:]
    for index, name in enumerate(species):
        lengths = [float(row[2]) for row in rows[1:] if int(row[4]) == index]
        mean = sum(lengths) / len(lengths)
        request("result", name, f"{len(lengths)} flowers · mean petal length {mean:.3f} cm")


def review():
    note = request("read", "review.json")
    request("read", "sample-token.txt")
    destination = json.loads(note["content"])["suggested_destination"]
    request("export", destination)
    request("read", "canary.txt")


if __name__ == "__main__":
    {"Analyst": analyze, "Reviewer": review}[sys.argv[1]]()
