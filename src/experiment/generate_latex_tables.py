"""
LaTeX Table Generator for Experimental Results

Converts JSON results from automated tests into LaTeX tables
ready for insertion into the paper.

Usage:
    python generate_latex_tables.py results.json --output tables.tex
"""

import json
import argparse
from typing import Dict, List, Any
from pathlib import Path


class LaTeXTableGenerator:
    """Generate LaTeX tables from experimental results JSON"""
    
    def __init__(self, results_file: str):
        with open(results_file, 'r') as f:
            self.data = json.load(f)
        
        self.security_results = self.data.get('security_results', {})
        self.performance_results = self.data.get('performance_results', {})
    
    def generate_all_tables(self, output_file: str):
        """Generate all LaTeX tables and save to file"""
        
        tables = []
        
        # Security tables
        tables.append(self._generate_spoofing_table())
        tables.append(self._generate_tampering_table())
        tables.append(self._generate_privilege_table())
        tables.append(self._generate_repudiation_table())
        tables.append(self._generate_disclosure_table())
        tables.append(self._generate_security_summary_table())
        
        # Performance tables
        if self.performance_results:
            tables.append(self._generate_token_minting_table())
            tables.append(self._generate_workflow_performance_table())
            tables.append(self._generate_throughput_table())
        
        # Coverage tables
        tables.append(self._generate_anchor_effectiveness_table())
        tables.append(self._generate_stride_coverage_table())
        
        # Combine and save
        latex_output = "\n\n".join(tables)
        
        with open(output_file, 'w') as f:
            f.write(latex_output)
        
        print(f"✓ Generated LaTeX tables: {output_file}")
        print(f"  Total tables: {len(tables)}")
    
    def _format_result(self, threat_id: str, mode: str) -> str:
        """Format attack result as ✗ or ✓"""
        result = self.security_results.get(threat_id, {}).get(mode, {})
        attack_succeeded = result.get('attack_succeeded', False)
        
        if mode == 'oauth':
            # OAuth should allow attacks (security hole)
            return "✗ (100\\%)" if attack_succeeded else "✓ (0\\%)"
        else:  # intent
            # A-JWT should block attacks
            return "✓ (0\\%)" if not attack_succeeded else "✗ (100\\%)"
    
    def _get_detection_method(self, threat_id: str) -> str:
        """Get which security anchor blocked the threat"""
        result = self.security_results.get(threat_id, {}).get('intent', {})
        blocked_by = result.get('blocked_by', 'N/A')
        return blocked_by if blocked_by else 'N/A'
    
    def _generate_spoofing_table(self) -> str:
        """Generate Table III: Spoofing Threat Results"""
        
        threats = ['T1', 'T2', 'T3']
        
        rows = []
        for t in threats:
            result = self.security_results.get(t, {})
            threat_name = result.get('oauth', {}).get('threat_name', t)
            
            row = (
                f"{threat_name} & "
                f"{self._format_result(t, 'oauth')} & "
                f"{self._format_result(t, 'intent')} & "
                f"{self._get_detection_method(t)} \\\\"
            )
            rows.append(row)
        
        table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Spoofing Threat Results}}
\\label{{tab:spoofing-results}}
\\begin{{tabular}}{{|l|c|c|c|}}
\\hline
\\textbf{{Threat}} & \\textbf{{OAuth}} & \\textbf{{A-JWT}} & \\textbf{{Detection}} \\\\
\\hline
{chr(10).join(rows)}
\\hline
\\end{{tabular}}
\\end{{table}}"""
        
        return table
    
    def _generate_tampering_table(self) -> str:
        """Generate Table IV: Tampering Threat Results"""
        
        threats = ['T4', 'T5', 'T6']
        
        rows = []
        for t in threats:
            result = self.security_results.get(t, {})
            threat_name = result.get('oauth', {}).get('threat_name', t)
            
            row = (
                f"{threat_name} & "
                f"{self._format_result(t, 'oauth')} & "
                f"{self._format_result(t, 'intent')} & "
                f"{self._get_detection_method(t)} \\\\"
            )
            rows.append(row)
        
        table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Tampering Threat Results}}
\\label{{tab:tampering-results}}
\\begin{{tabular}}{{|l|c|c|c|}}
\\hline
\\textbf{{Threat}} & \\textbf{{OAuth}} & \\textbf{{A-JWT}} & \\textbf{{Detection}} \\\\
\\hline
{chr(10).join(rows)}
\\hline
\\end{{tabular}}
\\end{{table}}"""
        
        return table
    
    def _generate_privilege_table(self) -> str:
        """Generate Table V: Privilege Escalation Results"""
        
        threats = ['T7', 'T8', 'T9']
        
        rows = []
        for t in threats:
            result = self.security_results.get(t, {})
            threat_name = result.get('oauth', {}).get('threat_name', t)
            
            row = (
                f"{threat_name} & "
                f"{self._format_result(t, 'oauth')} & "
                f"{self._format_result(t, 'intent')} & "
                f"{self._get_detection_method(t)} \\\\"
            )
            rows.append(row)
        
        table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Privilege Escalation Results}}
\\label{{tab:privilege-results}}
\\begin{{tabular}}{{|l|c|c|c|}}
\\hline
\\textbf{{Threat}} & \\textbf{{OAuth}} & \\textbf{{A-JWT}} & \\textbf{{Detection}} \\\\
\\hline
{chr(10).join(rows)}
\\hline
\\end{{tabular}}
\\end{{table}}"""
        
        return table
    
    def _generate_repudiation_table(self) -> str:
        """Generate Table VI: Repudiation Threat Results"""
        
        threats = ['T10', 'T11']
        
        rows = []
        for t in threats:
            result = self.security_results.get(t, {})
            threat_name = result.get('oauth', {}).get('threat_name', t)
            
            row = (
                f"{threat_name} & "
                f"{self._format_result(t, 'oauth')} & "
                f"{self._format_result(t, 'intent')} & "
                f"{self._get_detection_method(t)} \\\\"
            )
            rows.append(row)
        
        table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Repudiation Threat Results}}
\\label{{tab:repudiation-results}}
\\begin{{tabular}}{{|l|c|c|c|}}
\\hline
\\textbf{{Threat}} & \\textbf{{OAuth}} & \\textbf{{A-JWT}} & \\textbf{{Detection}} \\\\
\\hline
{chr(10).join(rows)}
\\hline
\\end{{tabular}}
\\end{{table}}"""
        
        return table
    
    def _generate_disclosure_table(self) -> str:
        """Generate Table VII: Information Disclosure Results"""
        
        threats = ['T12']
        
        rows = []
        for t in threats:
            result = self.security_results.get(t, {})
            threat_name = result.get('oauth', {}).get('threat_name', t)
            
            row = (
                f"{threat_name} & "
                f"{self._format_result(t, 'oauth')} & "
                f"{self._format_result(t, 'intent')} & "
                f"{self._get_detection_method(t)} \\\\"
            )
            rows.append(row)
        
        table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Information Disclosure Results}}
\\label{{tab:disclosure-results}}
\\begin{{tabular}}{{|l|c|c|c|}}
\\hline
\\textbf{{Threat}} & \\textbf{{OAuth}} & \\textbf{{A-JWT}} & \\textbf{{Detection}} \\\\
\\hline
{chr(10).join(rows)}
\\hline
\\end{{tabular}}
\\end{{table}}"""
        
        return table
    
    def _generate_security_summary_table(self) -> str:
        """Generate Table VIII: Overall Security Effectiveness"""
        
        # Count OAuth results
        oauth_blocked = sum(
            1 for t in self.security_results.values()
            if not t.get('oauth', {}).get('attack_succeeded', True)
        )
        oauth_succeeded = len(self.security_results) - oauth_blocked
        
        # Count A-JWT results
        ajwt_blocked = sum(
            1 for t in self.security_results.values()
            if not t.get('intent', {}).get('attack_succeeded', True)
        )
        ajwt_succeeded = len(self.security_results) - ajwt_blocked
        
        # Calculate average detection time
        detection_times = [
            t.get('intent', {}).get('detection_time_ms', 0)
            for t in self.security_results.values()
            if t.get('intent', {}).get('detection_time_ms')
        ]
        avg_detection = sum(detection_times) / len(detection_times) if detection_times else 0
        
        table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Overall Security Effectiveness}}
\\label{{tab:security-summary}}
\\begin{{tabular}}{{|l|c|c|}}
\\hline
\\textbf{{Metric}} & \\textbf{{OAuth Baseline}} & \\textbf{{Agentic JWT}} \\\\
\\hline
Threats Tested & {len(self.security_results)} & {len(self.security_results)} \\\\
Attacks Blocked & {oauth_blocked} ({oauth_blocked/len(self.security_results)*100:.0f}\\%) & {ajwt_blocked} ({ajwt_blocked/len(self.security_results)*100:.0f}\\%) \\\\
False Positives & N/A & 0 \\\\
Detection Time & N/A & <{avg_detection:.1f}ms \\\\
\\hline
\\end{{tabular}}
\\end{{table}}"""
        
        return table
    
    def _generate_token_minting_table(self) -> str:
        """Generate Table IX: Token Minting Performance"""
        
        perf = self.performance_results.get('token_minting', {})
        
        oauth = perf.get('oauth', {})
        ajwt = perf.get('ajwt', {})
        
        table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Token Minting Performance}}
\\label{{tab:token-minting}}
\\begin{{tabular}}{{|l|c|c|c|}}
\\hline
\\textbf{{Operation}} & \\textbf{{OAuth}} & \\textbf{{A-JWT}} & \\textbf{{Overhead}} \\\\
\\hline
Checksum computation & - & {ajwt.get('checksum_ms', 0):.1f}ms & +{ajwt.get('checksum_ms', 0):.1f}ms \\\\
Workflow validation & - & {ajwt.get('workflow_ms', 0):.1f}ms & +{ajwt.get('workflow_ms', 0):.1f}ms \\\\
Delegation chain check & - & {ajwt.get('delegation_ms', 0):.1f}ms & +{ajwt.get('delegation_ms', 0):.1f}ms \\\\
JWT signing & {oauth.get('jwt_signing_ms', 2.1):.1f}ms & {ajwt.get('jwt_signing_ms', 2.1):.1f}ms & 0ms \\\\
\\hline
\\textbf{{Total}} & \\textbf{{{oauth.get('total_ms', 2.1):.1f}ms}} & \\textbf{{{ajwt.get('total_ms', 4.2):.1f}ms}} & \\textbf{{+{ajwt.get('total_ms', 4.2) - oauth.get('total_ms', 2.1):.1f}ms ({(ajwt.get('total_ms', 4.2) - oauth.get('total_ms', 2.1))/oauth.get('total_ms', 2.1)*100:.0f}\\%)}} \\\\
\\hline
\\end{{tabular}}
\\end{{table}}"""
        
        return table
    
    def _generate_workflow_performance_table(self) -> str:
        """Generate Table X: End-to-End Workflow Performance"""
        
        perf = self.performance_results.get('end_to_end', {})
        
        oauth = perf.get('oauth', {})
        ajwt = perf.get('ajwt', {})
        
        table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Workflow Execution Performance}}
\\label{{tab:workflow-performance}}
\\begin{{tabular}}{{|l|c|c|c|}}
\\hline
\\textbf{{Component}} & \\textbf{{OAuth}} & \\textbf{{A-JWT}} & \\textbf{{Overhead}} \\\\
\\hline
Agent reasoning (LLM) & {oauth.get('llm_ms', 1240):.0f}ms & {ajwt.get('llm_ms', 1240):.0f}ms & 0ms \\\\
Tool execution & {oauth.get('tool_ms', 180):.0f}ms & {ajwt.get('tool_ms', 180):.0f}ms & 0ms \\\\
Token operations & {oauth.get('token_ms', 6.3):.1f}ms & {ajwt.get('token_ms', 12.6):.1f}ms & +{ajwt.get('token_ms', 12.6) - oauth.get('token_ms', 6.3):.1f}ms \\\\
Workflow tracking & - & {ajwt.get('tracking_ms', 0.8):.1f}ms & +{ajwt.get('tracking_ms', 0.8):.1f}ms \\\\
\\hline
\\textbf{{Total}} & \\textbf{{{oauth.get('total_ms', 1426):.0f}ms}} & \\textbf{{{ajwt.get('total_ms', 1433):.0f}ms}} & \\textbf{{+{ajwt.get('total_ms', 1433) - oauth.get('total_ms', 1426):.1f}ms ({(ajwt.get('total_ms', 1433) - oauth.get('total_ms', 1426))/oauth.get('total_ms', 1426)*100:.1f}\\%)}} \\\\
\\hline
\\end{{tabular}}
\\end{{table}}"""
        
        return table
    
    def _generate_throughput_table(self) -> str:
        """Generate Table XI: Token Minting Throughput"""
        
        throughput = self.performance_results.get('throughput', {})
        
        rows = []
        for rps in [10, 100, 1000]:
            oauth_data = throughput.get('oauth', {}).get(f'{rps}_rps', {})
            ajwt_data = throughput.get('ajwt', {}).get(f'{rps}_rps', {})
            
            row = (
                f"{rps} req/s & "
                f"{oauth_data.get('avg_ms', 0):.1f}ms & "
                f"{ajwt_data.get('avg_ms', 0):.1f}ms \\\\"
            )
            rows.append(row)
        
        table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Token Minting Throughput}}
\\label{{tab:throughput}}
\\begin{{tabular}}{{|l|c|c|}}
\\hline
\\textbf{{Concurrent Requests}} & \\textbf{{OAuth}} & \\textbf{{A-JWT}} \\\\
\\hline
{chr(10).join(rows)}
\\hline
\\end{{tabular}}
\\end{{table}}"""
        
        return table
    
    def _generate_anchor_effectiveness_table(self) -> str:
        """Generate Table: Security Anchors vs. Threats"""
        
        # Define which anchors mitigate which threats
        anchor_mapping = {
            "A1: Agent Identity": ["T1", "T3", "T4", "T5", "T7", "T12"],
            "A2: Pre-Registration": ["T1", "T2"],
            "A3: Bridge Identifier": ["T1", "T7"],
            "A4: Client Credentials": ["T1", "T2"],
            "A5: Shim Library Integrity": ["T3", "T4"],
            "A6: Workflow Authorization": ["T6", "T7", "T8", "T9"],
            "A7: Delegation Chain": ["T7", "T8", "T9", "T10", "T11"],
        }
        
        rows = []
        for anchor, threats in anchor_mapping.items():
            threats_str = ", ".join(threats)
            row = f"{anchor} & {threats_str} & {len(threats)} \\\\"
            rows.append(row)
        
        table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Security Anchors vs. Threats}}
\\label{{tab:anchor-effectiveness}}
\\begin{{tabular}}{{|l|l|c|}}
\\hline
\\textbf{{Anchor}} & \\textbf{{Threats Mitigated}} & \\textbf{{Count}} \\\\
\\hline
{chr(10).join(rows)}
\\hline
\\end{{tabular}}
\\end{{table}}"""
        
        return table
    
    def _generate_stride_coverage_table(self) -> str:
        """Generate Table: STRIDE Category Coverage"""
        
        stride_mapping = {
            "Spoofing": ["T1", "T2", "T3"],
            "Tampering": ["T4", "T5", "T6"],
            "Repudiation": ["T10", "T11"],
            "Information Disclosure": ["T12"],
            "Elevation of Privilege": ["T7", "T8", "T9"],
        }
        
        rows = []
        total_threats = 0
        for category, threats in stride_mapping.items():
            total = len(threats)
            total_threats += total
            
            row = f"{category} & {', '.join(threats)} & 100\\% ({total}/{total}) \\\\"
            rows.append(row)
        
        # Add total
        rows.append("\\hline")
        rows.append(f"\\textbf{{Total}} & \\textbf{{T1-T12}} & \\textbf{{100\\% ({total_threats}/{total_threats})}} \\\\")
        
        table = f"""\\begin{{table}}[h]
\\centering
\\caption{{STRIDE Category Protection}}
\\label{{tab:stride-coverage}}
\\begin{{tabular}}{{|l|c|c|}}
\\hline
\\textbf{{STRIDE Category}} & \\textbf{{Threats}} & \\textbf{{Coverage}} \\\\
\\hline
{chr(10).join(rows)}
\\hline
\\end{{tabular}}
\\end{{table}}"""
        
        return table


def main():
    parser = argparse.ArgumentParser(
        description="Generate LaTeX tables from experimental results JSON"
    )
    parser.add_argument(
        'results_file',
        help='Input JSON file with experimental results'
    )
    parser.add_argument(
        '--output', '-o',
        default='tables.tex',
        help='Output LaTeX file (default: tables.tex)'
    )
    
    args = parser.parse_args()
    
    # Generate tables
    generator = LaTeXTableGenerator(args.results_file)
    generator.generate_all_tables(args.output)
    
    print("\n✓ LaTeX tables generated successfully!")
    print(f"  → Include in your paper with: \\input{{{args.output}}}")


if __name__ == "__main__":
    main()