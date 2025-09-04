import json
import aiofiles
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from models import AnalysisResult

class ReportGenerator:
    @staticmethod
    async def generate_json_report(analysis_result: AnalysisResult, 
                                 output_path: Path) -> Path:
        """Generate JSON report"""
        report_data = {
            "analysis_id": analysis_result.analysis_id,
            "timestamp": analysis_result.timestamp.isoformat(),
            "input_file": analysis_result.input_file,
            "compilation": analysis_result.compilation.dict(),
            "findings": [finding.dict() for finding in analysis_result.findings],
            "summary": analysis_result.summary,
            "errors": analysis_result.errors,
            "report_generated_at": datetime.utcnow().isoformat()
        }
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write report
        async with aiofiles.open(output_path, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(report_data, indent=2, ensure_ascii=False))
        
        return output_path
    
    @staticmethod
    def generate_summary_stats(findings: list) -> Dict[str, Any]:
        """Generate summary statistics"""
        if not findings:
            return {
                "total_findings": 0,
                "severity_breakdown": {},
                "category_breakdown": {},
                "tool_breakdown": {}
            }
        
        severity_count = {}
        category_count = {}
        tool_count = {}
        
        for finding in findings:
            # Count by severity
            severity = finding.get('severity', 'Unknown')
            severity_count[severity] = severity_count.get(severity, 0) + 1
            
            # Count by category
            category = finding.get('category', 'Unknown')
            category_count[category] = category_count.get(category, 0) + 1
            
            # Count by tool
            tool = finding.get('tool', 'Unknown')
            tool_count[tool] = tool_count.get(tool, 0) + 1
        
        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_count,
            "category_breakdown": category_count,
            "tool_breakdown": tool_count
        }
