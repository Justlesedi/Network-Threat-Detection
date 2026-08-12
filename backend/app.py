from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from database import Database
from scanner import NetworkScanner
from detection import ThreatDetectionEngine
from config import Config
from apscheduler.schedulers.background import BackgroundScheduler
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Krypt", description="Network Threat Detection Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Database()
scanner = NetworkScanner()
detection_engine = ThreatDetectionEngine()
scheduler = BackgroundScheduler()
active_connections = []

@app.on_event("startup")
async def startup_event():
    logger.info("Starting Krypt...")
    scheduler.add_job(periodic_scan, "interval", seconds=Config.SCAN_INTERVAL)
    scheduler.start()
    logger.info("Network scanner scheduled")

@app.on_event("shutdown")
async def shutdown_event():
    scheduler.shutdown()
    db.close()
    logger.info("Krypt shutdown")

def periodic_scan():
    try:
        devices = scanner.scan_network()
        for device in devices:
            existing = db.get_device_by_mac(device["mac"])
            if not existing:
                new_device = db.add_device(device["mac"], device["ip"], device["hostname"])
                logger.info(f"New device discovered: {device['hostname']} ({device['ip']})")
                alert_data = {"is_new_device": True, "ip": device["ip"], "mac": device["mac"]}
                alerts = detection_engine.analyze(alert_data)
                for alert in alerts:
                    if detection_engine.deduplicate_alerts(new_device.id, alert["rule_id"]):
                        db.add_alert(new_device.id, alert["rule_id"], alert["severity"], alert["description"])
            else:
                db.update_device_last_seen(device["mac"])
        logger.info("Network scan completed")
    except Exception as e:
        logger.error(f"Error in periodic scan: {e}")

@app.get("/")
async def root():
    return {"message": "Krypt API running", "status": "healthy"}

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/devices")
async def get_devices():
    try:
        devices = db.get_all_devices()
        return {
            "devices": [
                {
                    "id": d.id,
                    "mac_address": d.mac_address,
                    "ip_address": d.ip_address,
                    "hostname": d.hostname,
                    "first_seen": d.first_seen,
                    "last_seen": d.last_seen,
                    "is_suspicious": d.is_suspicious
                }
                for d in devices
            ],
            "total": len(devices)
        }
    except Exception as e:
        logger.error(f"Error fetching devices: {e}")
        return {"error": str(e)}, 500

@app.get("/alerts")
async def get_alerts(limit: int = 10):
    try:
        alerts = db.get_recent_alerts(limit)
        return {
            "alerts": [
                {
                    "id": a.id,
                    "device_id": a.device_id,
                    "alert_type": a.alert_type,
                    "severity": a.severity,
                    "message": a.message,
                    "timestamp": a.timestamp
                }
                for a in alerts
            ],
            "total": len(alerts)
        }
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return {"error": str(e)}, 500

@app.get("/devices/{device_id}/alerts")
async def get_device_alerts(device_id: int, limit: int = 10):
    try:
        alerts = db.get_alerts_by_device(device_id, limit)
        return {
            "device_id": device_id,
            "alerts": [
                {
                    "id": a.id,
                    "alert_type": a.alert_type,
                    "severity": a.severity,
                    "message": a.message,
                    "timestamp": a.timestamp
                }
                for a in alerts
            ],
            "total": len(alerts)
        }
    except Exception as e:
        logger.error(f"Error fetching device alerts: {e}")
        return {"error": str(e)}, 500

@app.get("/stats")
async def get_stats():
    try:
        devices = db.get_all_devices()
        alerts = db.get_recent_alerts(100)
        suspicious_count = sum(1 for d in devices if d.is_suspicious)
        critical_alerts = sum(1 for a in alerts if a.severity == "critical")

        return {
            "total_devices": len(devices),
            "suspicious_devices": suspicious_count,
            "total_alerts": len(alerts),
            "critical_alerts": critical_alerts,
            "threat_level": detection_engine.get_threat_level([{"severity": a.severity} for a in alerts])
        }
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return {"error": str(e)}, 500

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        active_connections.remove(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=Config.HOST, port=Config.PORT)