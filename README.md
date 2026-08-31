# BCI Security Gateway

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22208029.svg)](https://doi.org/10.5281/zenodo.22208029)

Here you will find the artifact for my MSc Cybersecurity thesis at UCD. It is a prototype security gateway which sits inline between a simulated brain-computer interface device and the hub and dashboard downstream that consume its data. Full detail on the design and the evaluation is in the thesis document itself, this README covers what the code does and how to run it.

The gateway enforces four controls along with an input validation layer:

* **F1 Authentication** mutual TLS along with a per-device allowlist, so a device is accepted only when its certificate chains back to the testbed CA and its CN is one the gateway recognises.
* **F2 Integrity** an HMAC-SHA256 attached to every packet as it leaves the gateway and verified again at the hub, so any modification in transit is caught downstream.
* **F3 Anti-replay** a timestamp window together with strictly increasing sequence numbers per device, which rejects stale frames and duplicates alike.
* **F4 Behavioural monitoring** a per-device packet rate cap and a statistical anomaly detector which learns each device's normal channel distribution and flags values far outside it.
* **Input validation** a packet shape check that runs before either F2 or F3 sees the frame, so malformed input never reaches the rest of the logic.

There are six attack scripts in `attacks/`, each aiming to defeat one specific control, and each running several variants for thirteen in total.

## Pipeline

```
simulator -> gateway -> hub -> dashboard
            (mTLS)     (ws)  (ws)
```

The pipeline is four separate processes running locally, with Python asyncio on the backend and Vite and React for the dashboard. There is no Docker, no message queue and no database, since what matters in the artifact is the gateway itself rather than the infrastructure around it.

The gateway runs two WebSocket servers, one facing the device on port 9000 which terminates mutual TLS, and one facing the hub on 9001. Every inbound frame follows the same fixed path: the rate limiter, then JSON parsing, then the shape check, then a comparison of the packet's device ID against the CN authenticated at the handshake, then the anomaly detector, then anti-replay validation, then the HMAC attachment and finally the broadcast to the hub. A frame that fails any of these is dropped and the reason recorded in `gateway_events.log`, which is also the file the attack scripts read to produce their defender side results.

## Setup

You will need Python 3.8 or later, Node 18 or later, and openssl on the PATH.

```
pip install -r requirements.txt
cd dashboard && npm install && cd ..
bash certs/generate_certs.sh
```

The certificate script generates two separate CAs, one trusted by the gateway and one used by the spoofing attack, along with a gateway certificate, two device certificates and three further device certificates which exist purely as fixtures for the attack variants. Those three cover an expired certificate, one with an uppercase CN and one whose CN is a substring of a valid device ID. Everything is issued with 365 day validity, so the script will need running again once they expire.

## Running the secured pipeline

In four terminals:

```
python -m gateway.main --config config.json

python -m hub.main --mode secured --gateway-host 127.0.0.1 --gateway-port 9001 \
    --dashboard-port 8002 --config config.json

python -m simulator.main --host 127.0.0.1 --port 9000 \
    --cert certs/devices/device-001.crt \
    --key certs/devices/device-001.key \
    --ca-cert certs/ca/testbed-ca.crt

cd dashboard && npm run dev
```

The dashboard is then at http://localhost:5173.

It is worth using `127.0.0.1` rather than `localhost` throughout. On Windows the name resolution adds around two seconds to each connection, which is more than enough to distort the results of the timing sensitive attacks.

## Running the baseline pipeline

The baseline is the same pipeline with the gateway removed entirely, so the simulator talks straight to an undefended hub. This is what every attack is measured against.

```
python -m hub.main --mode baseline --port 8001 --dashboard-port 8002
python -m simulator.main --no-tls --host 127.0.0.1 --port 8001
cd dashboard && npm run dev
```

## One command launchers

Four terminals gets tedious quickly, so `run_secured.py` and `run_baseline.py` will each bring up an entire pipeline on their own.

```
python run_secured.py
python run_baseline.py
```

There is also `run_demo.py`, which starts the secured pipeline and then works through normal traffic, the attack suite and recovery, so the dashboard fills up while you watch rather than needing anything triggered by hand. It takes `--showcase` to sit idle with a live device instead of firing the attacks, `--manual` to step through the phases with Enter, and `--eeg-file` to stream a recorded EEG file in place of the synthetic signal. The `.bat` files in the repository root do the same on Windows.

### Choosing the interpreter on Windows

The `.bat` launchers locate a Python interpreter themselves rather than assuming a fixed path, checking for a conda install, then the `py` launcher, then whatever `python` resolves to, and taking the first one with a working `ssl` module. Conda installations need `Library\bin` and `DLLs` on the PATH before `ssl` will import at all, so those are added automatically when they apply.

If the wrong interpreter gets picked, or Python is somewhere unusual, set `BCI_PYTHON` to the one you want and the launchers will use it instead:

```
set BCI_PYTHON=C:\path\to\python.exe
run_secured.bat
```

The detection is only there for the `.bat` convenience wrappers. Running the modules directly as shown further up avoids the question entirely, and is the more reliable route if anything looks off.

## Attacks

To run all six against the secured pipeline:

```
python attacks/run_all.py --gateway-port 9000
```

And against the baseline, where the attacks with no baseline equivalent are skipped since there is no control present to compare against:

```
python attacks/run_all.py --baseline --hub-port 8001
```

Any of these can be run on its own as well, and each takes `--help` for its own options.

| ATK | Script | What it does | Variants | Blocked by |
|-----|--------|--------------|----------|------------|
| 1 | `spoof_device.py` | Presents a certificate the gateway ought to reject during the TLS handshake | untrusted CA, expired cert, no client cert | F1 (mTLS) |
| 2 | `replay_attack.py` | Captures genuine packets using a stolen device key and replays them byte for byte | delayed replay, in-session replay | F3 (anti-replay) |
| 3 | `tamper_mitm.py` | Sits on the gateway to hub link as a real relay and mutates the command field in transit | full mutation, partial mutation | F2 (HMAC) |
| 4 | `unauth_access.py` | Connects with a properly signed certificate whose CN is not on the allowlist | non-allowlisted, case mismatch, CN substring | F1 (allowlist) |
| 5 | `fuzz_input.py` | Sends fourteen malformed packets followed by five valid ones on the same connection | malformed battery | Input validation |
| 6 | `abnormal_device.py` | Authenticates legitimately, then floods packets and emits channel values well outside its own baseline | rate flood, abnormal channels | F4 |

ATK3 is an actual man in the middle rather than a simulated one. It spawns the relay along with a sidecar hub on a separate port and feeds its own short lived device traffic through the gateway, so the relay has genuine frames to tamper with.

ATK6 is the one scenario where a variant ends in detection rather than blocking. The rate flood is dropped at the cap, but the anomaly detector is alert only, so the flagged packets are still forwarded. This is deliberate rather than an oversight, since quietly dropping unusual neural data risks discarding a genuine physiological event.

A scenario passes only when every one of its variants is blocked, and an individual variant counts as blocked only when the attacker side and the defender side both agree that it was.

## Evaluation

The whole evaluation runs from a single orchestrator:

```
python evaluation/run_eval.py --mode both
```

This stands up both pipelines in turn, runs a phase of normal traffic to check for false positives, runs the attack suite, runs the per-packet overhead benchmark and writes all of it into `evaluation/results/`. Passing `--mode baseline` or `--mode secured` runs one side only.

The overhead benchmark can also be run by itself:

```
python evaluation/measure_overhead.py
```

The two F4 studies, the parameter sensitivity sweep and the extended false-positive check, are run separately since they exercise the detector directly rather than the live pipeline:

```
python evaluation/run_f4_studies.py
```

This writes `sensitivity_atk6.json` and `false_positive_extended.json`. The recorded EEG source is skipped if the dataset is not present locally, since it is a third party file rather than part of this repository. The detection rates are stable between runs, while the false alarm rates vary a little, as the synthetic signal carries unseeded noise.

The output is JSON holding both the attacker side counters, meaning whatever the attacking client actually observed, and the defender side counts read out of `gateway_events.log`, meaning what the gateway recorded while the attack was running. Comparing the baseline results against the secured ones is what isolates the gateway as the cause of the difference.

## Results

Everything in `evaluation/results/` comes from a real run rather than being example data. The headline figures are these:

* All six scenarios blocked or detected across all thirteen variants (`evaluation_summary.json` and `attack_results_secured.json`)
* No false rejections, no false rate limit drops and no false anomaly alerts across 2,404 legitimate packets, putting the upper bound at 0.16% on a 95% Wilson interval (`normal_operation_secured.json`)
* The gateway adding a mean of 0.0073 ms per packet and the HMAC check at the hub a further 0.0123 ms, measured over 50,000 iterations against the 4 ms inter-packet budget of a 250 Hz device (`overhead.json`)
* A sweep of the F4 parameters showing the trade off between detection and false alarms across different learning windows and z-score thresholds (`sensitivity_atk6.json`)
* An extended false positive check over 15,000 packets taken from six different signal sources, one of them a recorded EEG dataset rather than a synthetic one (`false_positive_extended.json`)

Connection level attack rates are given with 95% Wilson score confidence intervals rather than as bare percentages, since one hundred attempts per variant is a fairly small sample and a flat 0% would claim more than that sample can support.

The security outcomes here are deterministic and reproduce exactly, since a control either catches an attack or it does not. The timing figures are sampled measurements and will vary by a few percent between runs, with the p99 tail varying rather more, given that they depend on scheduling on a general purpose operating system.

## Configuration

The ports, certificate paths, HMAC key, allowlist and all four F4 parameters live in `config.json`, and every one of them can be overridden on the command line. The F4 defaults are a cap of 400 packets per second, a learning window of 300 packets, a z-score threshold of 6 and a hard channel bound of 300.

The HMAC key in `config.json` is a placeholder for the prototype and nothing more. A real deployment would derive a per-session key from the TLS handshake rather than shipping a shared secret inside a config file, and this is recorded as a limitation in the thesis.

## AI assistance

Claude (Anthropic) was used as a coding assistant during the implementation of this artifact. The system architecture, threat model, choice of controls and the design of the evaluation are my own, as is responsibility for all code in this repository.

> Anthropic. (2026). *Claude* (Opus 4.8) [Large language model]. https://claude.ai

## Repository layout

* `gateway/` the core artifact, holding F1 through F4 and the input validation
* `hub/` HMAC verification and forwarding on to the dashboard
* `simulator/` synthetic 8-channel EEG and P300 commands at 250 Hz, or a recorded EEG file instead
* `dashboard/` the React and Vite interface, five panels including the security event log and the threat monitor
* `attacks/` ATK1 through ATK6 along with the MitM relay and the shared log reading and statistics helpers
* `evaluation/` the orchestrator, the overhead benchmark, metrics collection and the results themselves
* `certs/` the certificate generator and the PKI tree it produces
