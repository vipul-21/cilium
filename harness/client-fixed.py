import os, socket, threading, time, uuid, queue, collections

# Closed-loop DNS load generator.
#
# Every arm offers the SAME load: a fixed number of unique FQDNs released on a
# fixed schedule, independent of how fast the agent answers. A slow agent
# therefore shows up as latency / failures / backlog, never as reduced input.

ZONE     = os.environ.get("ZONE", "app.applied-caas16.internal.api.openai.org")
KEEP     = "keepalive-fixed." + ZONE + "."
TOTAL    = int(os.environ.get("TOTAL_NAMES", "200000"))   # across the whole fleet
FLEET    = int(os.environ.get("FLEET", "30"))             # pods
SECONDS  = int(os.environ.get("DURATION", "600"))
WORKERS  = int(os.environ.get("WORKERS", "24"))
POD      = os.environ.get("HOSTNAME", "pod")

MY_NAMES = TOTAL // FLEET
RATE     = MY_NAMES / float(SECONDS)          # names/sec this pod must offer

lock     = threading.Lock()
offered  = [0]     # released by the pacer - identical in every arm by construction
done     = [0]
failed   = [0]
lat      = collections.deque(maxlen=20000)
ready    = threading.Event()
q        = queue.Queue()

def name(i):
    # Mirrors the production shape: 3 dynamic labels above the zone.
    # Trailing dot = fully qualified: glibc will not expand through the four
    # cluster search domains, so one lookup is exactly one query.
    return "10-%d-%d-%d-%s-%d.%s." % (
        (i // 65536) % 254 + 1, (i // 256) % 254 + 1, i % 254 + 1,
        uuid.uuid4().hex, 20000 + (i % 10000), ZONE)

def keepalive():
    """Pins the shared IP so its zombie is never reaped."""
    ip = None
    while ip is None:
        try:
            ip = socket.getaddrinfo(KEEP, None, socket.AF_INET)[0][4][0]
        except Exception:
            time.sleep(1)
    print("keepalive ip=%s" % ip, flush=True)
    ready.set()
    while True:
        try:
            s = socket.create_connection((ip, 80), timeout=10)
            print("keepalive CONNECTED", flush=True)
            while True:
                s.sendall(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: keep-alive\r\n\r\n")
                if not s.recv(8192):
                    raise IOError("closed")
                time.sleep(3)
        except Exception as e:
            print("keepalive reconnect: %s" % e, flush=True)
            time.sleep(2)

def worker():
    while True:
        n = q.get()
        t0 = time.time()
        try:
            socket.getaddrinfo(n, None, socket.AF_INET)
            d = time.time() - t0
            with lock:
                done[0] += 1
                lat.append(d)
        except Exception:
            with lock:
                failed[0] += 1
                lat.append(time.time() - t0)
        q.task_done()

def pacer():
    """Releases exactly MY_NAMES lookups over SECONDS, on schedule."""
    ready.wait()
    t0 = time.time()
    for i in range(MY_NAMES):
        target = t0 + i / RATE
        now = time.time()
        if target > now:
            time.sleep(target - now)
        q.put(name(i))
        with lock:
            offered[0] += 1
    print("PACER DONE offered=%d" % offered[0], flush=True)

def reporter():
    ready.wait()
    while True:
        time.sleep(10)
        with lock:
            o, d, f = offered[0], done[0], failed[0]
            s = sorted(lat)
        p50 = s[len(s)//2] if s else 0
        p99 = s[int(len(s)*0.99)] if s else 0
        print("offered=%d done=%d failed=%d backlog=%d p50=%.3f p99=%.3f"
              % (o, d, f, q.qsize(), p50, p99), flush=True)

threading.Thread(target=keepalive, daemon=True).start()
for _ in range(WORKERS):
    threading.Thread(target=worker, daemon=True).start()
threading.Thread(target=reporter, daemon=True).start()
threading.Thread(target=pacer, daemon=True).start()

while True:
    time.sleep(3600)
