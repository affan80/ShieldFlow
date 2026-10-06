# Shield Flow

Shield Flow is a terminal-based traffic monitoring and DDoS anomaly-detection prototype for Nginx access logs.

The dashboard uses a compact view up to 110 columns wide, with traffic metrics, detection signals, risk status, top source IPs, recent requests, events, system load, and log-ingestion health. Arrow-key navigation and mitigation controls are not implemented yet.

## Quick start (Python)

From the project directory, set up Python and start the sample log generator in terminal 1:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install rich
python3 generate_logs.py
```

In terminal 2, from the same project directory, start the dashboard:

```bash
source .venv/bin/activate
python3 shield_flow.py --log logs/access_test.log
```

Start the generator first so the file exists. The dashboard follows lines appended after it starts; it does not replay earlier entries. Stop each process with `Ctrl+C`. If you omit `--log`, the dashboard selects the newest `logs/access_*.log` file at startup.

## Quick start (Docker)

Run these commands from the project directory with Docker running. Each terminal uses the same bind-mounted `logs/` directory. In terminal 1, start the sample generator:

```bash
docker run --rm -it -v "$PWD:/app" -w /app python:3.12-slim python generate_logs.py
```

In terminal 2, start the dashboard:

```bash
docker run --rm -it -v "$PWD:/app" -w /app python:3.12-slim sh -c 'pip install --no-cache-dir rich && python shield_flow.py --log logs/access_test.log'
```

The first Docker command downloads the image. The dashboard command installs Rich in its temporary container each time. Stop both containers with `Ctrl+C`. This runs the existing log monitor; the Nginx edge, automatic mitigation, and Compose stack described in the design document have not been implemented.

## Run against a live Nginx server

Create the log directory first:

```bash
mkdir -p logs
```

In terminal 1, stream the remote Nginx access log into the file used by the dashboard:

```bash
ssh USER@SERVER_IP "tail -F /var/log/nginx/access.log" | tee -a logs/access_test.log
```

Replace `USER` and `SERVER_IP` with the SSH user and address of the Nginx server.

In terminal 2:

```bash
source .venv/bin/activate
python3 shield_flow.py --log logs/access_test.log
```

## Run the standalone server monitor

`shield_flow_server.py` can monitor any Nginx access-log file directly:

```bash
python3 shield_flow_server.py --log logs/access_test.log
```

If `--log` is omitted, it automatically selects the newest `logs/access_*.log` file:

```bash
python3 shield_flow_server.py
```

The tracked `example_collect_log.sh` script can be used to collect remote Nginx logs. Update `LINUX_USER` and `LINUX_HOST` in that script first, then run:

```bash
chmod +x example_collect_log.sh
./example_collect_log.sh
```

The collector writes timestamped files such as `logs/access_20261004_081500.log`, which `shield_flow_server.py` can discover automatically.

You can also run `python3 shield_flow.py` after starting the collector to monitor its latest file with the compact dashboard. The selected file is shown on screen; restart or pass `--log` if you want a different file.

## Troubleshoot zero readings

- The sample generator writes one successful request every two seconds: approximately `0.50` RPS, `0.0%` errors, and usually no attack signals are expected.
- Bandwidth is displayed in B/s, KiB/s, or MiB/s so small values remain visible.
- `WAITING` means no valid new requests have been read since startup. Check the on-screen log path and keep the generator or collector running.
- `IDLE` means no valid request has arrived within the configured window (10 seconds by default). Live metrics return to zero as requests expire; the cumulative `Parsed` count and recent requests remain visible.
- An increasing `Skipped` count means lines do not match the supported Nginx access-log format. A `LOG ERROR` event shows file-access problems.
- The RPS baseline learns for `WARMUP_SECONDS` (30 seconds by default), then compares traffic against previous samples. Error, bandwidth, and IP signals remain active during learning.
- Zero risk and `NO` signals can be healthy readings; the dashboard does not manufacture attack data.

## Generate test traffic against the configured server

`test.sh` sends normal traffic, bursts, invalid requests, mixed endpoints, sustained traffic, and an error burst to the target configured inside the script.

Set the `TARGET` value in `test.sh`, then run:

```bash
chmod +x test.sh
./test.sh
```

Run the log collector and monitor/dashboard at the same time so the generated requests appear live.

## Main files

- `shield_flow.py` - compact Rich dashboard with `--log` support
- `shield_flow_server.py` - standalone terminal monitor with `--log` support
- `generate_logs.py` - generates local sample Nginx traffic
- `example_collect_log.sh` - streams a remote Nginx access log into `logs/`
- `test.sh` - generates traffic against a configured web server
- `config/config.json` - detection thresholds and timing configuration

## Verify the dashboard fixes

```bash
python3 -B -m unittest discover -s tests -v
```
