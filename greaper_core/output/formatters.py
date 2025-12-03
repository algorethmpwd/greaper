"""
Output Formatters
Support for multiple output formats
"""

import csv
import io
import json
from datetime import datetime

from ..config import Config


class OutputFormatter:
    """Format scan results in multiple formats"""

    @staticmethod
    def format(data, output_format, output_file=None):
        """
        Format scan results in specified format

        Args:
            data: Data to format
            output_format: Format type (txt, json, csv, html, markdown)
            output_file: Optional file to save output

        Returns:
            Formatted output string
        """
        if output_format == "json":
            output = json.dumps(data, indent=2, default=str)

        elif output_format == "csv":
            output_buffer = io.StringIO()
            if isinstance(data, dict) and "vulnerabilities" in data:
                writer = csv.DictWriter(
                    output_buffer,
                    fieldnames=[
                        "timestamp",
                        "target",
                        "type",
                        "severity",
                        "url",
                        "parameter",
                        "payload",
                    ],
                )
                writer.writeheader()
                for vuln in data.get("vulnerabilities", []):
                    writer.writerow(vuln)
            else:
                writer = csv.writer(output_buffer)
                writer.writerow(["Timestamp", "Data"])
                writer.writerow([datetime.now().isoformat(), str(data)])

            output = output_buffer.getvalue()

        elif output_format == "html":
            output = f"""<!DOCTYPE html>
<html>
<head>
    <title>Greaper Scanner Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        .finding {{ background: #ecf0f1; padding: 10px; margin: 10px 0; border-left: 4px solid #3498db; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Greaper Scanner Report</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    <div class="summary">
        <h2>Scan Results</h2>
        <pre>{json.dumps(data, indent=2, default=str)}</pre>
    </div>
</body>
</html>"""

        elif output_format == "markdown":
            output = f"""# Greaper Scanner Report

**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Scan Results

```json
{json.dumps(data, indent=2, default=str)}
```
"""

        else:  # txt (default)
            output = str(data)

        # Save to file if specified
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output)
            print(
                f"{Config.COLOR_GREEN}[+] Results saved to {output_file} ({output_format} format){Config.COLOR_RESET}"
            )
            print(f"{Config.COLOR_GREEN}[+] Results saved to {output_file} ({output_format} format){Config.COLOR_RESET}")

        return output
