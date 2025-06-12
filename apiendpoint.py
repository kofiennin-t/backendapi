from flask import Flask, request, jsonify
import os
import base64
from datetime import datetime

app = Flask(__name__)

def get_alerts(offset, page_size):
    # Dummy data matching the expected schema from the Sentinel template
    alerts = [
        {
            "id": "1",
            "notificationType": "alert",
            "source": "Sitestore",
            "summary": "Sample alert detection",
            "content": "Detailed alert information",
            "severity": 3,
            "createdAt": datetime.now().isoformat(),
            "reviewed": False,
            "retained": True,
            "state": "new",
            "detectorId": "detector-001",
            "occurredAt": datetime.now().isoformat(),
            "firstSeenAt": datetime.now().isoformat(),
            "lastSeenAt": datetime.now().isoformat(),
            "collectors": ["collector1", "collector2"],
            "analyticEventId": "event-001",
            "analyticEventIndex": "index-001",
            "sourceIndex": "source-001",
            "sourceIdField": "id",
            "sourceIds": ["source1", "source2"],
            "threatInfo": {
                "severity": "high",
                "category": "malware"
            },
            "assets": ["asset1", "asset2"],
            "count": 1,
            "matchedRuleIds": ["rule1", "rule2"],
            "detectionQuads": []
        }
    ]
    return alerts[offset:offset + page_size]

@app.route('/api/alerts', methods=['GET'])
def handler():
    # Check authentication
    auth = request.headers.get('Authorization')
    expected_auth = 'Basic ' + base64.b64encode(
        f"{os.environ.get('USERNAME')}:{os.environ.get('PASSWORD')}".encode()
    ).decode()

    if not auth or auth != expected_auth:
        return jsonify({"error": "Unauthorized"}), 401

    # Extract query parameters
    offset = int(request.args.get('offset', 0))
    page_size = int(request.args.get('pageSize', 25))

    # Get alerts with pagination
    alerts = get_alerts(offset, page_size)

    # Return in format expected by Sentinel
    return jsonify({
        "content": alerts,
        "pagination": {
            "offset": offset,
            "pageSize": page_size,
            "total": len(alerts)  # In a real implementation, this would be the total count of all alerts
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)