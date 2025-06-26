from flask import Flask, request, jsonify
from threat_analysis_agent import ThreatAnalysisAgent

app = Flask(__name__)
agent = ThreatAnalysisAgent()

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data or 'report' not in data:
        return jsonify({'error': 'Missing "report" in request body'}), 400
    report_text = data['report']
    analysis_result = agent.analyze_threat_report(report_text)
    return jsonify({'analysis': analysis_result})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
