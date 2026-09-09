import os, socket, time, threading, collections

# Light "observer" client for the mixed-shape benchmark.
#
# Represents an ordinary endpoint sharing a node with a heavy FQDN generator.
# It resolves a SMALL, FIXED set of names, so it contributes almost nothing to
# the zombie list - but it takes the same name-shard and DNS cache locks, so its
# latency measures the collateral damage the heavy endpoint inflicts.

ZONE    = os.environ.get("OBS_ZONE", "app.applied-caas16.internal.api.openai.org")
NAMES   = int(os.environ.get("OBS_NAMES", "10"))    # fixed working set
RATE    = float(os.environ.get("OBS_RATE", "2"))    # lookups/sec for this pod
POD     = os.environ.get("HOSTNAME", "obs")

names = ["observer-%02d.%s." % (i, ZONE) for i in range(NAMES)]

lock = threading.Lock()
lat  = collections.deque(maxlen=20000)
done = [0]
fail = [0]

def resolve_loop():
    i = 0
    t0 = time.time()
    while True:
        target = t0 + i / RATE
        now = time.time()
        if target > now:
            time.sleep(target - now)
        n = names[i % len(names)]
        s = time.time()
        try:
            socket.getaddrinfo(n, None, socket.AF_INET)
            d = time.time() - s
            with lock:
                done[0] += 1; lat.append(d)
        except Exception:
            with lock:
                fail[0] += 1; lat.append(time.time() - s)
        i += 1

def reporter():
    while True:
        time.sleep(10)
        with lock:
            d, f, s = done[0], fail[0], sorted(lat)
        if not s:
            continue
        p = lambda q: s[min(int(len(s)*q), len(s)-1)]
        # OBS= prefix so the harness can grep observer lines unambiguously
        print("OBS done=%d failed=%d p50=%.3f p90=%.3f p99=%.3f max=%.3f"
              % (d, f, p(.50), p(.90), p(.99), s[-1]), flush=True)

threading.Thread(target=reporter, daemon=True).start()
resolve_loop()
