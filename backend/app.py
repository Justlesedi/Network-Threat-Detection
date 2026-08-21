from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from database import Database
from scanner import NetworkScanner
from detection import ThreatDetectionEngine
from config import Config
from apscheduler.schedulers.background import BackgroundScheduler
import logging
from datetime import datetime
import asyncio

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
current_scan = None

@app.on_event("startup")
async def startup_event():
    logger.info("Starting Krypt...")
    scheduler.start()
    logger.info("Krypt started")

@app.on_event("shutdown")
async def shutdown_event():
    scheduler.shutdown()
    db.close()
    logger.info("Krypt shutdown")

@app.get("/")
async def root():
    return {"message": "Krypt API running", "status": "healthy"}

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/scan")
async def start_scan():
    global current_scan
    
    def scan_callback(status):
        asyncio.run(broadcast_scan_progress(status))
    
    result = scanner.scan_network(callback=scan_callback)
    
    local_devices = result.get("local_devices", [])
    foreign_devices = result.get("foreign_devices", [])
    
    for device in local_devices:
        existing = db.get_device_by_mac(device["mac"])
        if not existing:
            db.add_device(device["mac"], device["ip"], device["hostname"])
            logger.info(f"New device: {device['hostname']} ({device['ip']})")
        else:
            db.update_device_last_seen(device["mac"])
    
    for device in foreign_devices:
        existing = db.get_device_by_mac(device["mac"])
        if not existing:
            new_dev = db.add_device(device["mac"], device["ip"], device["hostname"])
            db.mark_device_suspicious(new_dev.id)
            alert_data = {"is_new_device": True, "ip": device["ip"], "mac": device["mac"], "is_foreign": True}
            alerts = detection_engine.analyze(alert_data)
            for alert in alerts:
                db.add_alert(new_dev.id, alert["rule_id"], alert["severity"], alert["description"])
            logger.warning(f"Foreign device detected: {device['hostname']} ({device['ip']})")
        else:
            db.mark_device_suspicious(existing.id)
    
    return {
        "status": "complete",
        "local_devices": len(local_devices),
        "foreign_devices": len(foreign_devices),
        "total": len(local_devices) + len(foreign_devices),
        "network": result.get("network")
    }

@app.get("/scan/status")
async def scan_status():
    return {"scanning": scanner.scanning, "progress": scanner.scan_progress}

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

@app.websocket("/ws/scan")
async def websocket_scan(websocket):
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

async def broadcast_scan_progress(status: dict):
    for connection in active_connections:
        try:
            await connection.send_json(status)
        except Exception as e:
            logger.error(f"Error broadcasting: {e}")



@app.post("/scan")
async def start_scan():
    
    global current_scan
    
    try:
        logger.info("Network scan initiated")
        
        # Get scan results
        result = scanner.scan_network()
        
        if "error" in result:
            return {"status": "error", "message": result["error"]}, 500
        
        local_devices = result.get("local_devices", [])
        foreign_devices = result.get("foreign_devices", [])
        network = result.get("network", "Unknown")
        
        # Process local devices
        for device in local_devices:
            existing = db.get_device_by_mac(device["mac"])
            if not existing:
                db.add_device(device["mac"], device["ip"], device["hostname"])
                logger.info(f"✓ New device added: {device['hostname']} ({device['ip']})")
            else:
                db.update_device_last_seen(device["mac"])
        
        # Process foreign devices
        for device in foreign_devices:
            existing = db.get_device_by_mac(device["mac"])
            if not existing:
                new_dev = db.add_device(device["mac"], device["ip"], device["hostname"])
                db.mark_device_suspicious(new_dev.id)
                alert_data = {
                    "is_new_device": True,
                    "ip": device["ip"],
                    "mac": device["mac"],
                    "is_foreign": True
                }
                alerts = detection_engine.analyze(alert_data)
                for alert in alerts:
                    db.add_alert(new_dev.id, alert["rule_id"], alert["severity"], alert["description"])
                logger.warning(f"⚠️ Foreign device detected: {device['hostname']} ({device['ip']})")
            else:
                db.mark_device_suspicious(existing.id)
        
        return {
            "status": "success",
            "network_scanned": network,
            "local_devices": {
                "count": len(local_devices),
                "devices": [
                    {
                        "hostname": d["hostname"],
                        "ip": d["ip"],
                        "mac": d["mac"],
                        "type": "local"
                    }
                    for d in local_devices
                ]
            },
            "foreign_devices": {
                "count": len(foreign_devices),
                "devices": [
                    {
                        "hostname": d["hostname"],
                        "ip": d["ip"],
                        "mac": d["mac"],
                        "type": "foreign",
                        "risk": "high"
                    }
                    for d in foreign_devices
                ]
            },
            "total_devices": len(local_devices) + len(foreign_devices),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        return {"status": "error", "message": str(e)}, 500

@app.get("/scan/status")
async def scan_status():
    
    return {
        "scanning": scanner.scanning,
        "progress": scanner.scan_progress,
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=Config.HOST, port=Config.PORT)
