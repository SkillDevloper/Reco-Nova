"""Centralized logging for Reco-Nova."""

import logging
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / f"reco-nova-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
    ]
)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"reco-nova.{name}")


class AuditLogger:
    """Forensic audit logger for professional security assessments.
    
    Creates scan_log.txt in the output directory with detailed module execution tracking.
    Provides proof of work for professional audits.
    """
    
    def __init__(self, output_dir: Path, domain: str):
        self.output_dir = output_dir
        self.domain = domain
        self.log_file = output_dir / "scan_log.txt"
        self.phase_logs: list[dict] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        
        # Initialize log file
        self._init_log()
    
    def _init_log(self):
        """Initialize the audit log file."""
        header = f"""╔═══════════════════════════════════════════════════════════════════════════════╗
║                    RECO-NOVA FORENSIC AUDIT LOG                                ║
║                    Domain: {self.domain:<48} ║
║                    Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                                            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

AUDIT METHODOLOGY:
  Framework: Reco-Nova v1.2
  Developer: Daniyal Shahid
  Assessment Type: Automated Reconnaissance
  
════════════════════════════════════════════════════════════════════════════════

"""
        self.log_file.write_text(header, encoding='utf-8')
    
    def log_phase_start(self, phase_number: int, phase_name: str):
        """Log the start of a scanning phase."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[PHASE {phase_number}] {phase_name}\n"
        log_entry += f"  Start Time: {timestamp}\n"
        log_entry += f"  Status: RUNNING\n\n"
        
        self._append_log(log_entry)
        
        # Track for internal reference
        self.phase_logs.append({
            'phase': phase_number,
            'name': phase_name,
            'start_time': datetime.now(),
            'end_time': None,
            'findings_count': 0,
            'status': 'RUNNING'
        })
    
    def log_phase_end(self, phase_number: int, findings_count: int = 0, 
                      status: str = 'Success', error_message: str = None, details: str = None):
        """Log the completion of a scanning phase."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Find and update the phase record
        for phase in self.phase_logs:
            if phase['phase'] == phase_number:
                phase['end_time'] = datetime.now()
                phase['findings_count'] = findings_count
                phase['status'] = status
                break
        
        log_entry = f"  End Time: {timestamp}\n"
        log_entry += f"  Status: {status}\n"
        log_entry += f"  Findings: {findings_count}\n"
        
        if details:
            log_entry += f"  Details: {details}\n"
        
        if error_message:
            log_entry += f"  Error: {error_message}\n"
        
        # Calculate duration
        for phase in self.phase_logs:
            if phase['phase'] == phase_number and phase['start_time']:
                duration = phase['end_time'] - phase['start_time']
                log_entry += f"  Duration: {duration.total_seconds():.2f}s\n"
        
        log_entry += "\n" + "─" * 80 + "\n\n"
        
        self._append_log(log_entry)
    
    def log_module_execution(self, module_name: str, result_count: int, 
                            details: str = None, status: str = 'Success'):
        """Log individual module execution within a phase."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        log_entry = f"[MODULE] {module_name}\n"
        log_entry += f"  Timestamp: {timestamp}\n"
        log_entry += f"  Result Count: {result_count}\n"
        log_entry += f"  Status: {status}\n"
        
        if details:
            log_entry += f"  Details: {details}\n"
        
        log_entry += "\n"
        
        self._append_log(log_entry)
    
    def log_request_error(self, url: str, error_type: str, 
                         http_status: int = None, error_message: str = None):
        """
        Log detailed error trace for failed requests.
        Captures HTTP status codes and exception types for audit trail.
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        log_entry = f"[ERROR] Request Failed\n"
        log_entry += f"  Timestamp: {timestamp}\n"
        log_entry += f"  URL: {url}\n"
        log_entry += f"  Error Type: {error_type}\n"
        
        if http_status:
            log_entry += f"  HTTP Status: {http_status}\n"
            # Categorize HTTP errors
            if http_status == 403:
                log_entry += f"  Category: Forbidden (WAF/Access Control)\n"
            elif http_status == 401:
                log_entry += f"  Category: Unauthorized (Authentication Required)\n"
            elif http_status == 404:
                log_entry += f"  Category: Not Found\n"
            elif http_status == 429:
                log_entry += f"  Category: Rate Limited\n"
            elif http_status == 500:
                log_entry += f"  Category: Server Error\n"
            elif http_status == 502:
                log_entry += f"  Category: Bad Gateway\n"
            elif http_status == 503:
                log_entry += f"  Category: Service Unavailable\n"
            elif http_status == 504:
                log_entry += f"  Category: Gateway Timeout\n"
        
        if error_message:
            log_entry += f"  Message: {error_message}\n"
        
        log_entry += "\n"
        
        self._append_log(log_entry)
        logger.debug(f"Request error logged: {url} - {error_type}")
    
    def log_error_summary(self, phase_number: int, errors: dict):
        """
        Log error summary for a phase.
        errors dict should contain counts by error type/status code.
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        log_entry = f"[ERROR SUMMARY] Phase {phase_number}\n"
        log_entry += f"  Timestamp: {timestamp}\n"
        
        total_errors = sum(errors.values())
        log_entry += f"  Total Errors: {total_errors}\n"
        
        if errors:
            log_entry += "  Breakdown:\n"
            for error_type, count in sorted(errors.items(), key=lambda x: -x[1]):
                log_entry += f"    - {error_type}: {count}\n"
        
        log_entry += "\n"
        
        self._append_log(log_entry)
    
    def log_findings_summary(self, findings: dict):
        """Log a summary of all findings."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        summary = f"""
════════════════════════════════════════════════════════════════════════════════
                           FINDINGS SUMMARY
════════════════════════════════════════════════════════════════════════════════
  Generated: {timestamp}

  Subdomains Discovered: {findings.get('subdomains', 0)}
  Live Hosts Identified: {findings.get('live_hosts', 0)}
  API Endpoints Found: {findings.get('api_endpoints', 0)}
  URLs Discovered: {findings.get('urls', 0)}
  Parameters Extracted: {findings.get('parameters', 0)}
  JS Files Analyzed: {findings.get('js_files', 0)}
  Secrets Detected: {findings.get('secrets', 0)}
  Sensitive Files Found: {findings.get('sensitive_files', 0)}
  Cloud Assets Identified: {findings.get('cloud_assets', 0)}
  Critical Targets: {findings.get('critical_targets', 0)}
  High Priority Targets: {findings.get('high_targets', 0)}

════════════════════════════════════════════════════════════════════════════════

"""
        self._append_log(summary)
    
    def finalize_log(self, scan_duration: float = None):
        """Finalize the audit log with completion details."""
        self.end_time = datetime.now()
        
        footer = f"""════════════════════════════════════════════════════════════════════════════════
                              AUDIT COMPLETE
════════════════════════════════════════════════════════════════════════════════
  End Time: {self.end_time.strftime('%Y-%m-%d %H:%M:%S')}
"""
        if scan_duration:
            footer += f"  Total Duration: {scan_duration:.2f}s\n"
        
        footer += """  
  All phases completed. See above for detailed results.
  
  This log serves as proof of work for professional security assessments.
  Generated by Reco-Nova v1.2 - Developed by Daniyal Shahid
════════════════════════════════════════════════════════════════════════════════
"""
        self._append_log(footer)
    
    def _append_log(self, text: str):
        """Append text to the log file."""
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(text)


def get_audit_logger(output_dir: Path, domain: str) -> AuditLogger:
    """Factory function to create an AuditLogger instance."""
    return AuditLogger(output_dir, domain)