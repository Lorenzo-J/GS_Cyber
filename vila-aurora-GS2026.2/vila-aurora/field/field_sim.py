"""Simulador dos dispositivos de campo. Cada dispositivo tem cliente MQTT, certificado X.509 proprio e mTLS.
Dados 100% sinteticos. Uso: python field/field_sim.py --duration 600 --excursion-at 300 --excursion-len 120"""
import argparse, json, os, random, ssl, threading, time
import paho.mqtt.client as mqtt

PKI = os.environ.get("PKI", os.path.join(os.path.dirname(__file__), "..", "pki", "out"))

def mk_client(cn, host, port, on_message=None):
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cn)
    c.tls_set(ca_certs=f"{PKI}/ca.crt", certfile=f"{PKI}/devices/{cn}.crt", keyfile=f"{PKI}/devices/{cn}.key",
              tls_version=ssl.PROTOCOL_TLSv1_2)
    if on_message: c.on_message = on_message
    c.connect(host, port, 30); c.loop_start(); return c

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8883)
    ap.add_argument("--interval", type=float, default=2.0); ap.add_argument("--duration", type=float, default=120)
    ap.add_argument("--excursion-at", type=float, default=-1, help="s apos inicio: camara fria sobe acima de 8C")
    ap.add_argument("--excursion-len", type=float, default=120)
    ap.add_argument("--seed", type=int, default=7); ap.add_argument("--level0", type=float, default=60.0)
    a = ap.parse_args(); random.seed(a.seed)
    state = {"pump": "off", "level": a.level0}
    def on_cmd(cl, ud, m):
        try: cmd = json.loads(m.payload)
        except Exception: return
        if cmd.get("action") in ("start", "stop"): state["pump"] = "on" if cmd["action"] == "start" else "off"
    pump = mk_client("bomba-escola", a.host, a.port, on_cmd); pump.subscribe("vila/cmd/bomba-escola")
    cam = mk_client("sensor-camara-fria-ubs", a.host, a.port)
    niv = mk_client("sensor-nivel-escola", a.host, a.port)
    ene = mk_client("sensor-energia-centro", a.host, a.port)
    t0 = time.time(); n = 0
    while time.time() - t0 < a.duration:
        el = time.time() - t0; ts = time.time()
        exc = a.excursion_at >= 0 and a.excursion_at <= el < a.excursion_at + a.excursion_len
        temp = round(random.gauss(11.5 if exc else 4.5, 0.4), 2)
        state["level"] += (1.2 if state["pump"] == "on" else 0) - 0.25 + random.gauss(0, 0.05)
        state["level"] = max(0.0, min(100.0, state["level"]))
        cam.publish("vila/telemetria/sensor-camara-fria-ubs", json.dumps({"ts": ts, "temp_c": temp}))
        niv.publish("vila/telemetria/sensor-nivel-escola", json.dumps({"ts": ts, "level_pct": round(state["level"], 2)}))
        pump.publish("vila/telemetria/bomba-escola", json.dumps({"ts": ts, "state": state["pump"]}))
        ene.publish("vila/telemetria/sensor-energia-centro", json.dumps({"ts": ts, "watts": round(random.gauss(820, 40), 1)}))
        n += 1; time.sleep(a.interval)
    for c in (pump, cam, niv, ene): c.loop_stop(); c.disconnect()
    print(f"field_sim fim: {n} ciclos ({n*4} leituras)")
if __name__ == "__main__": main()
