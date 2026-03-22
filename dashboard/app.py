"""
AI-SOC Web Dashboard
====================
Web interface for monitoring AI-SOC services

Run with: python dashboard/app.py
Access at: http://localhost:3000
"""

from flask import Flask, render_template, jsonify, request
import subprocess
import json
import requests
from datetime import datetime

app = Flask(__name__)

# AI service endpoints
AI_SERVICES = {
    "ml-inference": {
        "url": "http://localhost:8500",
        "label": "ML Inference",
        "description": "Anomaly detection and threat classification"
    },
    "alert-triage": {
        "url": "http://localhost:8100",
        "label": "Alert Triage",
        "description": "LLM-powered alert analysis"
    },
    "rag-service": {
        "url": "http://localhost:8300",
        "label": "RAG Service",
        "description": "Security knowledge base retrieval"
    },
    "wazuh-integration": {
        "url": "http://localhost:8002",
        "label": "Wazuh Integration",
        "description": "SIEM alert forwarding and enrichment"
    },
    "feedback-service": {
        "url": "http://localhost:8400",
        "label": "Feedback Service",
        "description": "Alert persistence and analyst feedback"
    },
    "correlation-engine": {
        "url": "http://localhost:8600",
        "label": "Correlation Engine",
        "description": "Alert correlation and incident grouping"
    }
}

QUICK_LINKS = [
    {"name": "Grafana", "url": "http://localhost:3001", "description": "Metrics and dashboards"},
    {"name": "Wazuh Dashboard", "url": "https://localhost:443", "description": "SIEM alerts and agents"},
    {"name": "Prometheus", "url": "http://localhost:9090", "description": "Raw metrics"},
    {"name": "ChromaDB", "url": "http://localhost:8200", "description": "Vector database"},
    {"name": "Ollama", "url": "http://localhost:11434", "description": "LLM server"},
]


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/status')
def get_status():
    """Get Docker container status"""
    try:
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{json .}}'],
            capture_output=True,
            text=True,
            timeout=5
        )

        containers = []
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        container = json.loads(line)
                        containers.append({
                            'name': container.get('Names', 'unknown'),
                            'status': container.get('Status', 'unknown'),
                            'ports': container.get('Ports', ''),
                            'state': container.get('State', 'unknown')
                        })
                    except json.JSONDecodeError:
                        continue

        healthy_count = sum(1 for c in containers if 'healthy' in c['status'].lower() or 'up' in c['status'].lower())
        total_count = len(containers)

        overall_status = 'offline'
        if total_count > 0:
            if healthy_count == total_count:
                overall_status = 'healthy'
            elif healthy_count > 0:
                overall_status = 'partial'

        return jsonify({
            'status': overall_status,
            'containers': containers,
            'healthy_count': healthy_count,
            'total_count': total_count,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'containers': [],
            'healthy_count': 0,
            'total_count': 0
        })


@app.route('/api/services')
def get_services():
    """
    Proxy health checks to all AI services.
    Returns health status for ML Inference, Alert Triage, RAG, and Wazuh Integration.
    """
    services_status = []

    for service_id, config in AI_SERVICES.items():
        service_result = {
            "id": service_id,
            "label": config["label"],
            "description": config["description"],
            "url": config["url"],
            "docs_url": f"{config['url']}/docs",
            "status": "offline",
            "details": {}
        }

        try:
            resp = requests.get(
                f"{config['url']}/health",
                timeout=3,
                verify=False
            )
            if resp.status_code == 200:
                service_result["status"] = "healthy"
                try:
                    service_result["details"] = resp.json()
                except Exception:
                    service_result["details"] = {"message": "OK"}
            else:
                service_result["status"] = "degraded"
                service_result["details"] = {"http_status": resp.status_code}
        except requests.exceptions.ConnectionError:
            service_result["status"] = "offline"
            service_result["details"] = {"error": "Connection refused"}
        except requests.exceptions.Timeout:
            service_result["status"] = "timeout"
            service_result["details"] = {"error": "Request timed out"}
        except Exception as e:
            service_result["status"] = "error"
            service_result["details"] = {"error": str(e)}

        services_status.append(service_result)

    healthy = sum(1 for s in services_status if s["status"] == "healthy")
    return jsonify({
        "services": services_status,
        "healthy_count": healthy,
        "total_count": len(services_status),
        "timestamp": datetime.now().isoformat()
    })


@app.route('/api/alerts/recent')
def get_recent_alerts():
    """
    Get recent alert triage results from the alert-triage service.
    Returns cached test data if the service is unavailable.
    """
    try:
        resp = requests.get(
            "http://localhost:8100/alerts/recent",
            timeout=5
        )
        if resp.status_code == 200:
            return jsonify(resp.json())
    except Exception:
        pass

    # Return informative fallback data if service is down
    return jsonify({
        "alerts": [
            {
                "alert_id": "demo-001",
                "timestamp": datetime.now().isoformat(),
                "rule_description": "SSH Brute Force Attempt",
                "severity": "HIGH",
                "confidence": 0.92,
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110.001",
                "source_ip": "192.168.1.100",
                "recommendation": "Block source IP and review SSH configuration",
                "status": "demo"
            },
            {
                "alert_id": "demo-002",
                "timestamp": datetime.now().isoformat(),
                "rule_description": "Suspicious PowerShell Execution",
                "severity": "CRITICAL",
                "confidence": 0.88,
                "mitre_tactic": "Execution",
                "mitre_technique": "T1059.001",
                "source_ip": "10.0.0.50",
                "recommendation": "Investigate PowerShell history and parent process",
                "status": "demo"
            }
        ],
        "note": "Alert triage service offline - showing demo data",
        "timestamp": datetime.now().isoformat()
    })


@app.route('/api/ml/stats')
def get_ml_stats():
    """
    Proxy to ML inference /models endpoint to get loaded model information.
    Returns service-unavailable info if ML service is down.
    """
    try:
        resp = requests.get("http://localhost:8500/models", timeout=5)
        if resp.status_code == 200:
            return jsonify(resp.json())
    except Exception:
        pass

    return jsonify({
        "models": [],
        "status": "offline",
        "message": "ML inference service is not running",
        "timestamp": datetime.now().isoformat()
    })


@app.route('/api/test-alert', methods=['POST'])
def test_alert():
    """
    Send a test alert to the alert-triage service and return the AI analysis result.
    Proxies to http://localhost:8100/analyze
    """
    test_payload = {
        "alert_id": f"test-{int(datetime.now().timestamp())}",
        "timestamp": datetime.now().isoformat(),
        "source_ip": "192.168.1.200",
        "destination_ip": "10.0.0.1",
        "rule_id": "5710",
        "rule_level": 10,
        "rule_description": "Multiple failed SSH login attempts (Dashboard Test)",
        "full_log": "Oct 01 12:00:00 server sshd[1234]: Failed password for invalid user admin from 192.168.1.200 port 54321 ssh2",
        "agent_name": "test-agent",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001"
    }

    try:
        resp = requests.post(
            "http://localhost:8100/analyze",
            json=test_payload,
            timeout=60  # LLM analysis can take time
        )
        if resp.status_code == 200:
            result = resp.json()
            result["test_mode"] = True
            result["input_alert"] = test_payload
            return jsonify(result)
        else:
            return jsonify({
                "error": f"Alert triage returned HTTP {resp.status_code}",
                "test_mode": True,
                "input_alert": test_payload
            }), resp.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({
            "error": "Alert triage service is not running (connection refused)",
            "test_mode": True,
            "input_alert": test_payload,
            "demo_result": {
                "severity": "HIGH",
                "confidence": 0.91,
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110.001 - Password Guessing",
                "summary": "SSH brute force attack detected from 192.168.1.200. Multiple failed authentication attempts targeting the SSH service indicate automated credential stuffing or dictionary attack.",
                "recommended_actions": [
                    "Block source IP 192.168.1.200 at firewall",
                    "Review /var/log/auth.log for successful logins",
                    "Enable fail2ban if not already active",
                    "Consider moving SSH to non-standard port"
                ]
            }
        }), 503
    except Exception as e:
        return jsonify({
            "error": str(e),
            "test_mode": True
        }), 500


@app.route('/api/logs/<container>')
def get_logs(container):
    """Get logs for a specific container"""
    try:
        result = subprocess.run(
            ['docker', 'logs', '--tail', '100', container],
            capture_output=True,
            text=True,
            timeout=5
        )

        return jsonify({
            'container': container,
            'logs': result.stdout + result.stderr,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        return jsonify({
            'container': container,
            'error': str(e),
            'logs': ''
        })


if __name__ == '__main__':
    print("=" * 60)
    print("AI-SOC Dashboard Starting...")
    print("=" * 60)
    print("Access the dashboard at: http://localhost:3000")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    app.run(host='0.0.0.0', port=3000, debug=False)
