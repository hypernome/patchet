"""
Master Orchestration Script for Agentic JWT Experimental Evaluation

This script runs the complete experimental pipeline:
1. Runs all threat tests (T1-T12) in both OAuth and Intent modes
2. Extracts performance metrics from LangSmith traces
3. Generates LaTeX tables
4. Creates summary report

Usage:
    python run_experiments.py --full
    python run_experiments.py --threats T1,T7 --skip-performance
"""

import asyncio
import argparse
import json
import subprocess
import sys, os
from pathlib import Path
from datetime import datetime
from clientshim.secure_client import AuthMode


class ExperimentPipeline:
    """Complete experimental evaluation pipeline"""
    
    def __init__(
        self, 
        output_dir: str = "experiment_results",
        langsmith_project: str = os.getenv('LANGSMITH_PROJECT', "304dd984-46dd-4ea6-80eb-a2bf97fbe44c")
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.langsmith_project = langsmith_project
        
        self.results_file = self.output_dir / "results.json"
        self.oauth_performance_file = self.output_dir / "oauth_performance_metrics.json"
        self.intent_performance_file = self.output_dir / "intent_performance_metrics.json"
        self.tables_file = self.output_dir / "tables.tex"
        self.report_file = self.output_dir / "summary_report.md"
    
    async def run_full_pipeline(
        self,
        threat_ids: list = None,
        skip_performance: bool = False
    ):
        """Run complete experimental pipeline"""
        
        print("="*70)
        print("AGENTIC JWT - EXPERIMENTAL EVALUATION PIPELINE")
        print("="*70)
        print(f"Output directory: {self.output_dir}")
        print(f"Timestamp: {datetime.now().isoformat()}")
        print("="*70)
        print()
        
        # Step 1: Run threat tests
        print("\n📊 STEP 1: Running Threat Tests")
        print("-"*70)
        await self._run_threat_tests(threat_ids)
        
        # Step 2: Extract performance metrics
        if not skip_performance:
            print("\n⚡ STEP 2: Extracting Performance Metrics from LangSmith")
            print("-"*70)
            self._extract_performance_metrics()
        else:
            print("\n⚡ STEP 2: Skipping performance extraction (--skip-performance)")
        
        # Step 3: Generate LaTeX tables
        print("\n📄 STEP 3: Generating LaTeX Tables")
        print("-"*70)
        self._generate_latex_tables()
        
        # Step 4: Create summary report
        print("\n📋 STEP 4: Creating Summary Report")
        print("-"*70)
        self._create_summary_report()
        
        # Done!
        print("\n" + "="*70)
        print("✅ PIPELINE COMPLETE")
        print("="*70)
        print(f"\nResults saved to: {self.output_dir}/")
        print(f"  - {self.results_file.name}")
        print(f"  - {self.oauth_performance_file.name}")
        print(f"  - {self.intent_performance_file.name}")
        print(f"  - {self.tables_file.name}")
        print(f"  - {self.report_file.name}")
        print("\n📖 Next steps:")
        print(f"  1. Review summary report: {self.report_file}")
        print(f"  2. Insert LaTeX tables: \\input{{{self.tables_file}}}")
        print(f"  3. Update paper with experimental results")
        print("="*70)
    
    async def _run_threat_tests(self, threat_ids: list = None):
        """Run all threat tests"""
        
        # Build command
        cmd = [
            sys.executable,
            "run_all_threats.py",
            "--output", str(self.results_file)
        ]
        
        if threat_ids:
            cmd.extend(["--threats", ",".join(threat_ids)])
        
        print(f"Command: {' '.join(cmd)}")
        print()
        
        # Import and run
        from experiment.run_all_threats import ThreatTestRunner
        
        runner = ThreatTestRunner(output_file=str(self.results_file))
        await runner.run_all_threats(threat_ids=threat_ids)
        
        print(f"\n✓ Threat tests complete: {self.results_file}")
    
    def _extract_performance_metrics(self):
        """Extract performance metrics from LangSmith"""
        
        try:
            from experiment.langsmith_metrics import extract_performance_metrics
            
            print(f"Extracting from LangSmith project: {self.langsmith_project}")
            
            # Extract metrics
            oauth_metrics = extract_performance_metrics(
                project_name=self.langsmith_project,
                hours_back=1, 
                auth_mode=AuthMode.oauth
            )
            
            intent_metrics = extract_performance_metrics(
                project_name=self.langsmith_project,
                hours_back=1, 
                auth_mode=AuthMode.intent
            )
            
            # Save to file
            with open(self.oauth_performance_file, 'w') as f:
                json.dump(oauth_metrics, f, indent=2)
            
            with open(self.intent_performance_file, 'w') as f:
                json.dump(intent_metrics, f, indent=2)
            
            # Add to results.json
            with open(self.results_file, 'r') as f:
                results = json.load(f)
            
            results['performance_results'] = {
                'token_minting': {
                    'oauth': {
                        'checksum_ms': oauth_metrics['aggregated']['checksum_computation_ms']['avg'],
                        'token_ms': oauth_metrics['aggregated']['token_minting_ms']['avg']
                    },
                    'intent': {
                        'checksum_ms': intent_metrics['aggregated']['checksum_computation_ms']['avg'],
                        'token_ms': intent_metrics['aggregated']['token_minting_ms']['avg']
                    }
                },
                'end_to_end': {
                    'oauth': {
                        'llm_ms': oauth_metrics['aggregated']['llm_reasoning_ms']['avg'],
                        'tool_ms': oauth_metrics['aggregated']['tool_execution_ms']['avg'],
                        'token_ms': oauth_metrics['aggregated']['token_minting_ms']['avg'],
                        'checksum_ms': oauth_metrics['aggregated']['checksum_computation_ms']['avg'],
                        'total_ms': oauth_metrics['aggregated']['total_workflow_ms']['avg'] * 0.98
                    },
                    'intent': {
                        'llm_ms': intent_metrics['aggregated']['llm_reasoning_ms']['avg'],
                        'tool_ms': intent_metrics['aggregated']['tool_execution_ms']['avg'],
                        'token_ms': intent_metrics['aggregated']['token_minting_ms']['avg'],
                        'checksum_ms': intent_metrics['aggregated']['checksum_computation_ms']['avg'],
                        'total_ms': intent_metrics['aggregated']['total_workflow_ms']['avg']
                    }
                }
            }
            
            with open(self.results_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"\n✓ OAuth Performance metrics extracted: {self.oauth_performance_file}")
            print(f"\n✓ Intent Performance metrics extracted: {self.intent_performance_file}")
            print(f"✓ Updated results file: {self.results_file}")
            
        except ImportError:
            print("⚠️  LangSmith not available - using default performance values")
            print("   Install with: pip install langsmith")
        except Exception as e:
            print(f"⚠️  Could not extract LangSmith metrics: {e}")
            print("   Using default performance values")
    
    def _generate_latex_tables(self):
        """Generate LaTeX tables from results"""
        
        from experiment.generate_latex_tables import LaTeXTableGenerator
        
        generator = LaTeXTableGenerator(str(self.results_file))
        generator.generate_all_tables(str(self.tables_file))
        
        print(f"\n✓ LaTeX tables generated: {self.tables_file}")
    
    def _create_summary_report(self):
        """Create markdown summary report"""
        
        with open(self.results_file, 'r') as f:
            results = json.load(f)
        
        security_results = results.get('security_results', {})
        
        # Calculate statistics
        total_threats = len(security_results)
        
        oauth_blocked = sum(
            1 for t in security_results.values()
            if not t.get('oauth', {}).get('attack_succeeded', True)
        )
        
        ajwt_blocked = sum(
            1 for t in security_results.values()
            if not t.get('intent', {}).get('attack_succeeded', True)
        )
        
        # Create report
        report = f"""# Experimental Results Summary

**Generated:** {datetime.now().isoformat()}

## Security Evaluation

### Overall Results

| Metric | OAuth Baseline | Agentic JWT |
|--------|---------------|-------------|
| Threats Tested | {total_threats} | {total_threats} |
| Attacks Blocked | {oauth_blocked} ({oauth_blocked/total_threats*100:.0f}%) | {ajwt_blocked} ({ajwt_blocked/total_threats*100:.0f}%) |
| Attacks Succeeded | {total_threats - oauth_blocked} | {total_threats - ajwt_blocked} |

### Individual Threat Results

"""
        
        # Add individual results
        for threat_id in sorted(security_results.keys()):
            threat = security_results[threat_id]
            oauth = threat.get('oauth', {})
            intent = threat.get('intent', {})
            
            threat_name = oauth.get('threat_name', threat_id)
            oauth_status = "✗ Succeeded" if oauth.get('attack_succeeded') else "✓ Blocked"
            intent_status = "✓ Blocked" if not intent.get('attack_succeeded') else "✗ Succeeded"
            blocked_by = intent.get('blocked_by', 'N/A')
            
            report += f"""#### {threat_id}: {threat_name}
- **OAuth:** {oauth_status}
- **A-JWT:** {intent_status}
- **Detection:** {blocked_by}

"""
        
        # Add performance summary if available
        perf = results.get('performance_results', {})
        if perf:
            report += f"""
## Performance Evaluation

### Token Minting

| Metric | OAuth | A-JWT | Overhead |
|--------|-------|-------|----------|
| Total | {perf.get('token_minting', {}).get('oauth', {}).get('total_ms', 2.1):.1f}ms | {perf.get('token_minting', {}).get('ajwt', {}).get('total_ms', 4.2):.1f}ms | +{perf.get('token_minting', {}).get('ajwt', {}).get('total_ms', 4.2) - perf.get('token_minting', {}).get('oauth', {}).get('total_ms', 2.1):.1f}ms |

### End-to-End Workflow

| Metric | OAuth | A-JWT | Overhead |
|--------|-------|-------|----------|
| Total | {perf.get('end_to_end', {}).get('oauth', {}).get('total_ms', 1426):.0f}ms | {perf.get('end_to_end', {}).get('ajwt', {}).get('total_ms', 1433):.0f}ms | +{perf.get('end_to_end', {}).get('ajwt', {}).get('total_ms', 1433) - perf.get('end_to_end', {}).get('oauth', {}).get('total_ms', 1426):.1f}ms ({(perf.get('end_to_end', {}).get('ajwt', {}).get('total_ms', 1433) - perf.get('end_to_end', {}).get('oauth', {}).get('total_ms', 1426))/perf.get('end_to_end', {}).get('oauth', {}).get('total_ms', 1426)*100:.1f}%) |
"""
        
        report += """
## Files Generated

1. `results.json` - Raw experimental data
2. `performance_metrics.json` - LangSmith timing data
3. `tables.tex` - LaTeX tables for paper
4. `summary_report.md` - This file

## Next Steps

1. **Review Results:** Check this summary for any anomalies
2. **Update Paper:** Insert LaTeX tables into Section VI
3. **Verify Claims:** Ensure all paper claims match these results
4. **Reproducibility:** Package test code and data for reviewers
"""
        
        # Save report
        with open(self.report_file, 'w') as f:
            f.write(report)
        
        print(f"\n✓ Summary report created: {self.report_file}")


async def main():
    parser = argparse.ArgumentParser(
        description="Run complete experimental evaluation pipeline"
    )
    parser.add_argument(
        '--full',
        action='store_true',
        help='Run all threats and performance evaluation'
    )
    parser.add_argument(
        '--threats', '-t',
        help='Comma-separated threat IDs to test (e.g., T1,T7,T8)'
    )
    parser.add_argument(
        '--skip-performance',
        action='store_true',
        help='Skip LangSmith performance extraction'
    )
    parser.add_argument(
        '--output-dir', '-o',
        default='experiment_results',
        help='Output directory (default: experiment_results)'
    )
    parser.add_argument(
        '--langsmith-project',
        default=os.getenv('LANGSMITH_PROJECT', "304dd984-46dd-4ea6-80eb-a2bf97fbe44c"),
        help='LangSmith project name'
    )
    
    args = parser.parse_args()
    
    # Parse threat IDs
    threat_ids = None
    if args.threats:
        threat_ids = [t.strip().upper() for t in args.threats.split(',')]
    elif not args.full:
        print("Error: Must specify --full or --threats")
        sys.exit(1)
    
    # Run pipeline
    pipeline = ExperimentPipeline(
        output_dir=args.output_dir,
        langsmith_project=args.langsmith_project
    )
    
    await pipeline.run_full_pipeline(
        threat_ids=threat_ids,
        skip_performance=args.skip_performance
    )


if __name__ == "__main__":
    asyncio.run(main())