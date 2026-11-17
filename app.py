"""SentinelPulse AI — local Flask SOC dashboard with Groq Copilot (no Supabase)."""
from flask import Flask, jsonify, request, send_file, render_template
from dotenv import load_dotenv
from datetime import datetime
from pathlib import Path
import csv, io, json, os, random, ipaddress, requests

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
INCIDENTS_FILE = DATA_DIR / "incidents.json"
SETTINGS_FILE = DATA_DIR / "settings.json"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or "sentinelpulse-local-dev-key-change-before-deployment"
AI_PROVIDER = os.getenv("AI_PROVIDER", "groq").lower()
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_MODEL = os.getenv("AI_MODEL", "llama-3.3-70b-versatile")
ALLOWED_ATTACKS = {"Brute Force": ("T1110", "Critical"), "SQL Injection": ("T1190", "High"), "DDoS": ("T1499", "Medium")}
DEFAULT_SETTINGS = {"theme":"dark","refresh_interval":30,"notifications":True,"compact_mode":False,"analyst_name":"Security Analyst"}

def load_incidents():
    if INCIDENTS_FILE.exists():
        try:
            rows = json.loads(INCIDENTS_FILE.read_text(encoding="utf-8"))
            if isinstance(rows, list): return rows
        except (json.JSONDecodeError, OSError): pass
    from mock_data import THREAT_LOGS
    rows = [dict(x) for x in THREAT_LOGS]
    save_incidents(rows)
    return rows

def save_incidents(rows):
    INCIDENTS_FILE.write_text(json.dumps(rows, indent=2), encoding="utf-8")

def load_settings():
    data = dict(DEFAULT_SETTINGS)
    if SETTINGS_FILE.exists():
        try: data.update(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError): pass
    return data

def save_settings(data):
    SETTINGS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

def incidents(): return load_incidents()
def now_stamp(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

@app.get("/")
def home(): return render_template("index.html")

@app.get("/api/health")
def health():
    return jsonify({"status":"ok","storage":"local-json","ai_provider":AI_PROVIDER,"ai_configured":bool(AI_PROVIDER=="groq" and AI_API_KEY),"ai_model":AI_MODEL if AI_API_KEY else None})

@app.get("/api/kpis")
def kpis():
    rows=incidents(); active=[r for r in rows if r["status"]=="Active"]
    weights={"Critical":5,"High":3,"Medium":1,"Low":0}
    score=max(0,100-sum(weights.get(r.get("severity"),0) for r in active))
    return jsonify({"total_logs":len(rows),"active_critical":sum(r.get("severity")=="Critical" for r in active),"mitigated":sum(r["status"]=="Mitigated" for r in rows),"health_score":score})

@app.get("/api/threats")
def threats():
    rows=incidents()
    q=request.args.get("q","").strip().lower()
    severity=request.args.get("severity","All")
    status=request.args.get("status","All")
    if severity!="All": rows=[r for r in rows if r.get("severity")==severity]
    if status!="All": rows=[r for r in rows if r.get("status")==status]
    if q: rows=[r for r in rows if any(q in str(r.get(k,"")).lower() for k in ("timestamp","source_ip","attack_type","mitre_id","severity","status","description"))]
    return jsonify(sorted(rows,key=lambda r:r.get("timestamp",""),reverse=True))

@app.get("/api/analytics")
def analytics():
    rows=incidents(); active=[r for r in rows if r["status"]=="Active"]
    types={}
    severities={}
    for row in active:
        types[row["attack_type"]]=types.get(row["attack_type"],0)+1
        severities[row["severity"]]=severities.get(row["severity"],0)+1
    return jsonify({"attack_types":types,"severities":severities,"total":len(rows),"active":len(active),"mitigated":len(rows)-len(active)})

@app.post("/api/simulate")
def simulate():
    data=request.get_json(silent=True) or {}; attack=data.get("type")
    if attack not in ALLOWED_ATTACKS: return jsonify({"error":"Unsupported simulation type."}),400
    mitre,severity=ALLOWED_ATTACKS[attack]
    # RFC 5737 documentation range: never attribute this to a real attacker.
    ip=str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("198.51.100.0"))+random.randint(1,254)))
    rows=incidents(); item={"id":max([int(r.get("id",0)) for r in rows] or [0])+1,"timestamp":now_stamp(),"source_ip":ip,"attack_type":attack,"mitre_id":mitre,"severity":severity,"status":"Active","description":f"Simulated {attack} event generated in the demo environment.","simulated":True}
    rows.append(item);save_incidents(rows)
    return jsonify(item),201

@app.post("/api/mitigate")
def mitigate():
    data=request.get_json(silent=True) or {}; incident_id=data.get("id")
    rows=incidents()
    for row in rows:
        if str(row.get("id"))==str(incident_id) and row.get("status")=="Active":
            row["status"]="Mitigated";row["mitigated_at"]=now_stamp();save_incidents(rows)
            return jsonify({"status":"Mitigated","id":incident_id})
    return jsonify({"error":"Incident not found or already mitigated."}),404

@app.get("/api/settings")
def get_settings(): return jsonify(load_settings())

@app.post("/api/settings")
def update_settings():
    incoming=request.get_json(silent=True) or {}; current=load_settings()
    allowed={"theme","refresh_interval","notifications","compact_mode","analyst_name"}
    for key in allowed:
        if key in incoming:
            value=incoming[key]
            if key=="theme" and value not in ("dark","light"): continue
            if key=="refresh_interval":
                try: value=max(10,min(360,int(value)))
                except (ValueError,TypeError): continue
            if key in ("notifications","compact_mode"): value=bool(value)
            if key=="analyst_name": value=str(value)[:50]
            current[key]=value
    save_settings(current);return jsonify(current)

@app.get("/api/notifications")
def notifications():
    active=[r for r in incidents() if r["status"]=="Active"]
    active.sort(key=lambda r:r.get("timestamp",""),reverse=True)
    return jsonify([{"id":r["id"],"title":f'{r["severity"]} · {r["attack_type"]}',"detail":f'Incident from {r["source_ip"]}',"timestamp":r["timestamp"],"severity":r["severity"]} for r in active[:12]])

@app.post("/api/copilot/chat")
def copilot_chat():
    data=request.get_json(silent=True) or {}; message=data.get("message","")
    if not isinstance(message,str) or not message.strip() or len(message)>6000:
        return jsonify({"error":"Enter a message between 1 and 6000 characters."}),400
    if AI_PROVIDER!="groq" or not AI_API_KEY:
        return jsonify({"error":"Groq is not configured. Add AI_API_KEY to your local .env file and restart Flask."}),503
    rows=incidents()
    context=[{k:r.get(k) for k in ("timestamp","source_ip","attack_type","mitre_id","severity","status","description","simulated")} for r in rows[-100:]]
    system=("You are SentinelPulse AI, a defensive SOC copilot. Use only the supplied local incident records. "
            "Separate facts from hypotheses, never invent telemetry, state when data is insufficient, and provide safe defensive investigation guidance. "
            "Do not execute actions or claim to block traffic or mitigate incidents. Simulator records are synthetic demo data.\n"
            f"Incident records (JSON): {json.dumps(context)}")
    try:
        response=requests.post("https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization":f"Bearer {AI_API_KEY}","Content-Type":"application/json"},
            json={"model":AI_MODEL,"messages":[{"role":"system","content":system},{"role":"user","content":message.strip()}],"temperature":0.2,"max_tokens":1000},
            timeout=45)
        if response.status_code>=400:
            try: detail=response.json().get("error",{}).get("message","")
            except ValueError: detail=""
            return jsonify({"error":f"Groq API error ({response.status_code}). {detail or 'Check your API key, model and quota.'}"}),502
        answer=response.json()["choices"][0]["message"]["content"]
        return jsonify({"answer":answer,"incident_context_count":len(context),"model":AI_MODEL})
    except requests.RequestException as exc: return jsonify({"error":f"Could not reach Groq API: {exc}"}),502

@app.get("/api/export")
def export():
    rows=incidents(); out=io.StringIO(); writer=csv.writer(out)
    writer.writerow(["ID","Timestamp","Source IP","Attack Type","MITRE ID","Severity","Status","Description","Simulated"])
    for r in rows: writer.writerow([r.get(k,"") for k in ("id","timestamp","source_ip","attack_type","mitre_id","severity","status","description","simulated")])
    return send_file(io.BytesIO(out.getvalue().encode("utf-8-sig")),mimetype="text/csv",as_attachment=True,download_name="sentinelpulse_incidents.csv")

@app.get("/api/reports")
def reports():
    rows=incidents()
    return jsonify({"generated_at":now_stamp(),"total":len(rows),"active":sum(r["status"]=="Active" for r in rows),"mitigated":sum(r["status"]=="Mitigated" for r in rows),"critical":sum(r["severity"]=="Critical" and r["status"]=="Active" for r in rows),"recent":rows[:10]})

if __name__=="__main__":
    app.run(host="127.0.0.1",port=5000,debug=os.getenv("FLASK_DEBUG","true").lower()=="true")
