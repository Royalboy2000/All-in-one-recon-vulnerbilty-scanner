import json
import datetime
import os

def generate_report(db, logger):
    logger.info("Gathering data for HTML Report...")
    findings = db.get_findings()

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_filename = f"redsentry_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    # Organize findings by Module -> Target -> Type
    report_data = {}

    for f in findings:
        # f: (id, module, target, type, data, timestamp)
        module = f[1]
        target = f[2]
        f_type = f[3]
        data = f[4]

        if module not in report_data:
            report_data[module] = {}
        if target not in report_data[module]:
            report_data[module][target] = []

        # Parse data if JSON
        try:
            parsed_data = json.loads(data)
        except:
            parsed_data = data

        report_data[module][target].append({
            "type": f_type,
            "data": parsed_data,
            "time": f[5]
        })

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedSentry Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e1e; color: #e0e0e0; margin: 0; padding: 20px; }}
        h1 {{ color: #ff5555; border-bottom: 2px solid #ff5555; padding-bottom: 10px; }}
        h2 {{ color: #50fa7b; margin-top: 30px; }}
        h3 {{ color: #8be9fd; }}
        .module-section {{ background-color: #282a36; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        .target-section {{ margin-left: 20px; border-left: 2px solid #6272a4; padding-left: 15px; }}
        .finding {{ background-color: #44475a; padding: 10px; margin-bottom: 10px; border-radius: 4px; }}
        .finding-title {{ font-weight: bold; color: #f1fa8c; }}
        pre {{ background-color: #000; padding: 10px; border-radius: 4px; overflow-x: auto; color: #50fa7b; }}
        .timestamp {{ font-size: 0.8em; color: #6272a4; float: right; }}
        .summary {{ background-color: #44475a; padding: 15px; border-radius: 8px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>RedSentry Final Report</h1>
    <div class="summary">
        <p><strong>Generated on:</strong> {timestamp}</p>
        <p><strong>Total Modules Run:</strong> {len(report_data)}</p>
        <p><strong>Total Findings:</strong> {len(findings)}</p>
    </div>
"""

    for module, targets in report_data.items():
        html_content += f"""
    <div class="module-section">
        <h2>Module: {module}</h2>
"""
        for target, items in targets.items():
            html_content += f"""
        <div class="target-section">
            <h3>Target: {target}</h3>
"""
            for item in items:
                # Format data based on type
                data_display = item['data']
                if isinstance(data_display, (list, dict)):
                    data_display = f"<pre>{json.dumps(data_display, indent=2)}</pre>"
                else:
                    data_display = f"<pre>{data_display}</pre>"

                html_content += f"""
            <div class="finding">
                <span class="timestamp">{item['time']}</span>
                <div class="finding-title">{item['type']}</div>
                {data_display}
            </div>
"""
            html_content += "        </div>"
        html_content += "    </div>"

    html_content += """
</body>
</html>
"""

    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(html_content)

    return report_filename
