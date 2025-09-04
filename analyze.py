#!/usr/bin/env python3
import asyncio
import shutil
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import uuid

from models import AnalysisResult, AnalysisFinding, CompilationResult
from utils.file_handler import FileHandler
from utils.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SolidityAnalysisEngine:
    def __init__(self):
        self.analysis_id = str(uuid.uuid4())
        self.workspace_dir: Optional[Path] = None
        
    async def analyze_file(self, input_path: str, output_dir: str = "./reports") -> Dict[str, Any]:
        """Analyze a Solidity file or directory"""
        try:
            input_path = Path(input_path).resolve()
            output_dir = Path(output_dir).resolve()
            
            logger.info(f"Starting analysis: {self.analysis_id}")
            logger.info(f"Input: {input_path}")
            logger.info(f"Output: {output_dir}")
            
            if not input_path.exists():
                raise ValueError(f"Input path does not exist: {input_path}")
            
            # Setup workspace
            contract_files = await self.setup_workspace(input_path)
            
            # Run analysis
            result = await self.run_analysis(str(input_path), contract_files)
            
            # Generate report
            report_path = await self.generate_report(result, output_dir)
            
            logger.info(f"Analysis completed: {len(result.findings)} findings")
            
            return {
                "success": True,
                "analysis_id": self.analysis_id,
                "report_path": str(report_path),
                "findings_count": len(result.findings),
                "summary": result.summary
            }
            
        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            return {
                "success": False,
                "analysis_id": self.analysis_id,
                "error": str(e)
            }
        
        finally:
            await self.cleanup()
    
    async def setup_workspace(self, input_path: Path) -> List[Path]:
        """Setup analysis workspace"""
        self.workspace_dir = FileHandler.create_temp_workspace(f"analysis-{self.analysis_id}-")
        logger.info(f"Workspace: {self.workspace_dir}")
        
        # Copy input to workspace
        contract_files = FileHandler.copy_input_to_workspace(input_path, self.workspace_dir)
        logger.info(f"Found {len(contract_files)} Solidity files")
        
        return contract_files
    
    async def run_analysis(self, input_path: str, contract_files: List[Path]) -> AnalysisResult:
        """Run complete analysis pipeline"""
        logger.info("🔬 Starting analysis pipeline...")
        
        # Initialize result
        result = AnalysisResult(
            analysis_id=self.analysis_id,
            timestamp=datetime.utcnow(),
            input_file=input_path,
            compilation=CompilationResult(success=False, framework='unknown'),
            findings=[],
            summary={}
        )
        
        try:
            # Step 1: Compile contracts
            compilation_result = await self.compile_contracts()
            result.compilation = compilation_result
            
            if compilation_result.success:
                # Step 2: Flatten contracts
                await self.flatten_contracts()
                
                # Step 3: Run analysis tools
                findings = await self.run_analysis_tools(contract_files)
                result.findings = findings
                
                # Step 4: Generate summary
                result.summary = ReportGenerator.generate_summary_stats(
                    [f.dict() for f in findings]
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Analysis pipeline error: {str(e)}")
            result.errors.append({"type": "PIPELINE_ERROR", "message": str(e)})
            return result
    
    async def compile_contracts(self) -> CompilationResult:
        """Compile contracts using Hardhat"""
        logger.info("🔨 Compiling contracts...")
        
        try:
            # Initialize npm project
            if not (self.workspace_dir / 'package.json').exists():
                await self.run_command(['npm', 'init', '-y'])
            
            # Install Hardhat dependencies
            if not (self.workspace_dir / 'node_modules').exists():
                logger.info("Installing Hardhat and dependencies...")
                await self.run_command([
                    'npm', 'install', '--save-dev', '--silent',
                    'hardhat@^2.26.0', '@openzeppelin/contracts', '--legacy-peer-deps'
                ], timeout=180)
            
            # Create Hardhat config
            await self.create_hardhat_config()
            
            # Compile
            await self.run_command(['npx', 'hardhat', 'compile', '--force'], timeout=180)
            
            # Collect artifacts
            artifacts = await self.collect_artifacts()
            
            return CompilationResult(
                success=True,
                framework='hardhat',
                artifacts=artifacts
            )
            
        except Exception as e:
            logger.error(f"Compilation failed: {str(e)}")
            return CompilationResult(
                success=False,
                framework='hardhat',
                error=str(e)
            )
    
    async def create_hardhat_config(self):
        """Create Hardhat configuration"""
        config_content = '''
module.exports = {
  solidity: {
    compilers: [
      { version: "0.8.21" },
      { version: "0.8.19" },
      { version: "0.8.0" },
      { version: "0.7.6" }
    ],
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  paths: {
    sources: "./contracts",
    artifacts: "./artifacts",
    cache: "./cache"
  },
  networks: {
    hardhat: {}
  }
};
        '''.strip()
        
        config_file = self.workspace_dir / 'hardhat.config.js'
        config_file.write_text(config_content)
    
    async def collect_artifacts(self) -> List[Dict]:
        """Collect compilation artifacts"""
        artifacts = []
        artifacts_dir = self.workspace_dir / 'artifacts' / 'contracts'
        
        if not artifacts_dir.exists():
            return artifacts
        
        for artifact_file in artifacts_dir.rglob('*.json'):
            if '.dbg.json' in artifact_file.name:
                continue
            
            try:
                with open(artifact_file, 'r') as f:
                    artifact_data = json.load(f)
                
                if 'abi' in artifact_data and 'bytecode' in artifact_data:
                    artifacts.append({
                        'contract_name': artifact_data.get('contractName'),
                        'source_name': artifact_data.get('sourceName'),
                        'abi': artifact_data['abi'],
                        'bytecode': artifact_data['bytecode']
                    })
            
            except Exception as e:
                logger.warning(f"Failed to parse artifact {artifact_file}: {e}")
        
        return artifacts
    
    async def flatten_contracts(self):
        """Flatten contracts for analysis"""
        logger.info("Flattening contracts...")
        
        flattened_dir = self.workspace_dir / 'flattened'
        flattened_dir.mkdir(exist_ok=True)
        
        contract_files = FileHandler.find_solidity_files(self.workspace_dir / 'contracts')
        
        for contract_file in contract_files:
            try:
                output_file = flattened_dir / contract_file.name
                
                # Try Hardhat flatten
                try:
                    flattened_content = await self.run_command([
                        'npx', 'hardhat', 'flatten', str(contract_file)
                    ], timeout=30)
                    output_file.write_text(flattened_content)
                except:
                    # Fallback: copy original file
                    shutil.copy2(contract_file, output_file)
                
                logger.info(f"Processed {contract_file.name}")
                
            except Exception as e:
                logger.warning(f"Failed to process {contract_file.name}: {e}")
    
    async def run_analysis_tools(self, contract_files: List[Path]) -> List[AnalysisFinding]:
        """Run analysis tools"""
        logger.info("Running analysis tools...")
        
        # Run tools in parallel
        tasks = [
            self.run_solhint(),
            self.run_slither(),
            self.run_mythril(contract_files),
            self.run_gas_analysis(contract_files)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        tool_names = ['solhint', 'slither', 'mythril', 'gas-analyzer']
        
        all_findings = []
        
        for i, result in enumerate(results):
            tool_name = tool_names[i]
            if isinstance(result, Exception):
                logger.error(f"{tool_name} failed: {str(result)}")
            else:
                all_findings.extend(result)
                logger.info(f"{tool_name}: {len(result)} findings")
        
        return all_findings
    
    async def run_solhint(self) -> List[AnalysisFinding]:
        """Run Solhint analysis"""
        try:
            # Create Solhint config
            config = {
                "extends": ["solhint:recommended"],
                "rules": {
                    "compiler-version": ["error", "^0.8.0"],
                    "gas-consumption": "warn"
                }
            }
            
            config_file = self.workspace_dir / '.solhint.json'
            config_file.write_text(json.dumps(config, indent=2))
            
            # Run Solhint
            try:
                output = await self.run_command([
                    'solhint', 'contracts/*.sol', '--formatter', 'json'
                ], timeout=60)
                
                results = json.loads(output or '[]')
                
                findings = []
                if isinstance(results, list):
                    for result in results:
                        if isinstance(result, dict) and 'filePath' in result:
                            findings.append(AnalysisFinding(
                                tool='solhint',
                                contract=Path(result['filePath']).stem,
                                category=self.categorize_solhint_rule(result.get('ruleId')),
                                severity=self.map_solhint_severity(result.get('severity')),
                                title=result.get('ruleId', 'Unknown'),
                                description=result.get('message', ''),
                                location={
                                    'file': result.get('filePath'),
                                    'line': result.get('line'),
                                    'column': result.get('column')
                                }
                            ))
                
                return findings
            
            except subprocess.CalledProcessError:
                # Solhint might not be installed, skip
                logger.warning("Solhint not available, skipping...")
                return []
            
        except Exception as e:
            logger.error(f"Solhint error: {str(e)}")
            return []
    
    async def run_slither(self) -> List[AnalysisFinding]:
        """Run Slither analysis"""
        try:
            flattened_dir = self.workspace_dir / 'flattened'
            
            try:
                # Run Slither on flattened contracts
                output = await self.run_command_with_results([
                    'slither', str(flattened_dir), '--json', '/dev/stdout'
                ], timeout=120)
                
                if output.strip():
                    results = json.loads(output)
                    detectors = results.get('results', {}).get('detectors', [])
                    
                    findings = []
                    for detector in detectors:
                        findings.append(AnalysisFinding(
                            tool='slither',
                            contract=detector.get('elements', [{}])[0].get('name', 'unknown'),
                            category='security',
                            severity=self.map_slither_severity(detector.get('impact')),
                            title=detector.get('check', 'Unknown'),
                            description=detector.get('description', ''),
                            location=detector.get('elements', [{}])[0].get('source_mapping', {})
                        ))
                    
                    return findings
                else:
                    return []
            
            except subprocess.CalledProcessError as e:
                # Slither might not be installed, skip
                logger.warning(f"Slither command failed: {e}")
                return []
            except Exception as e:
                logger.warning(f"Slither analysis error: {e}")
                return []
            
        except Exception as e:
            logger.error(f"Slither error: {str(e)}")
            return []
    
    async def run_mythril(self, contract_files: List[Path]) -> List[AnalysisFinding]:
        """Run Mythril analysis with proper error handling for multi-contract files"""
        try:
            logger.info("Starting Mythril analysis pipeline...")
            findings = []
            
            for contract_file in contract_files:
                try:
                    # Analyze all contracts in the file using their compiled artifacts
                    contract_findings = await self.run_mythril_on_all_contracts(contract_file)
                    findings.extend(contract_findings)
                
                except Exception as e:
                    logger.warning(f"Mythril analysis failed for {contract_file.name}: {e}")
                    # If Mythril fails due to solc issues, create an informational finding
                    if "SolcInstallationError" in str(e) or "solc" in str(e).lower():
                        findings.append(AnalysisFinding(
                            tool='mythril',
                            contract=contract_file.stem,
                            category='security',
                            severity='Info',
                            title='Mythril Analysis Failed',
                            description=f'Mythril security analysis failed: {str(e)}',
                            location={'file': str(contract_file), 'line': 1},
                            recommendation='This may be due to solc compatibility issues. Consider running on a different platform.'
                        ))
            
            if not findings:
                logger.info("Mythril completed successfully but found no security issues")
            
            return findings
            
        except Exception as e:
            logger.error(f"Mythril error: {str(e)}")
            return []
    
    async def run_gas_analysis(self, contract_files: List[Path]) -> List[AnalysisFinding]:
        """Run gas optimization analysis"""
        findings = []
        
        for contract_file in contract_files:
            try:
                content = contract_file.read_text()
                contract_name = contract_file.stem
                gas_findings = self.analyze_gas_patterns(content, contract_name)
                findings.extend(gas_findings)
            except Exception as e:
                logger.warning(f"Gas analysis failed for {contract_file}: {e}")
        
        return findings
    
    def analyze_gas_patterns(self, code: str, contract_name: str) -> List[AnalysisFinding]:
        """Analyze code for gas optimization patterns"""
        findings = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            line_num = i + 1
            line_clean = line.strip()
            
            # Pattern 1: Storage operations in loops
            if any(keyword in line_clean for keyword in ['for(', 'for ']) and \
               any(op in line_clean for op in ['.push(', '=']):
                findings.append(AnalysisFinding(
                    tool='gas-analyzer',
                    contract=contract_name,
                    category='gas',
                    severity='Medium',
                    title='Storage Operation in Loop',
                    description='Storage operations in loops consume high gas. Consider using memory or optimizing loop structure.',
                    location={'line': line_num, 'code': line_clean},
                    recommendation='Cache storage reads in memory variables or restructure the loop.'
                ))
            
            # Pattern 2: Potential underflow/overflow
            if '-=' in line_clean and 'require(' not in line_clean:
                findings.append(AnalysisFinding(
                    tool='gas-analyzer',
                    contract=contract_name,
                    category='security',
                    severity='High',
                    title='Potential Underflow',
                    description='Subtraction without overflow check detected.',
                    location={'line': line_num, 'code': line_clean},
                    recommendation='Add SafeMath library or require() checks before subtraction.'
                ))
            
            # Pattern 3: Multiple storage reads
            if line_clean.count('[') > 1 and '=' in line_clean:
                findings.append(AnalysisFinding(
                    tool='gas-analyzer',
                    contract=contract_name,
                    category='gas',
                    severity='Low',
                    title='Multiple Storage Reads',
                    description='Multiple storage reads detected. Consider caching in memory variable.',
                    location={'line': line_num, 'code': line_clean},
                    recommendation='Store frequently accessed storage values in memory variables.'
                ))
        
        return findings
    
    async def run_command(self, cmd: List[str], timeout: int = 60) -> str:
        """Run shell command with timeout"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=self.workspace_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            if process.returncode != 0:
                raise subprocess.CalledProcessError(
                    process.returncode, cmd, output=stdout, stderr=stderr
                )
            
            return stdout.decode('utf-8')
            
        except asyncio.TimeoutError:
            if 'process' in locals():
                process.kill()
            raise TimeoutError(f"Command timed out: {' '.join(cmd)}")
    
    async def run_command_with_results(self, cmd: List[str], timeout: int = 60) -> str:
        """Run shell command that may return results even with non-zero exit codes"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=self.workspace_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            # For tools like Slither, exit code 255 is normal when findings exist
            # Return stdout regardless of exit code if there's output
            output = stdout.decode('utf-8')
            if output.strip():
                return output
            elif process.returncode != 0:
                raise subprocess.CalledProcessError(
                    process.returncode, cmd, output=stdout, stderr=stderr
                )
            
            return output
            
        except asyncio.TimeoutError:
            if 'process' in locals():
                process.kill()
            raise TimeoutError(f"Command timed out: {' '.join(cmd)}")
    
    # Helper methods for severity mapping
    def categorize_solhint_rule(self, rule_id: str) -> str:
        if not rule_id:
            return 'maintainability'
        if 'gas' in rule_id or 'optimization' in rule_id:
            return 'gas'
        if 'security' in rule_id:
            return 'security'
        return 'maintainability'
    
    def map_solhint_severity(self, severity: str) -> str:
        mapping = {'error': 'High', 'warn': 'Medium', 'info': 'Low'}
        return mapping.get(severity, 'Low')
    
    def map_slither_severity(self, impact: str) -> str:
        mapping = {'High': 'High', 'Medium': 'Medium', 'Low': 'Low', 'Informational': 'Info'}
        return mapping.get(impact, 'Low')
    
    def map_mythril_severity(self, severity: str) -> str:
        mapping = {'High': 'High', 'Medium': 'Medium', 'Low': 'Low', 'high': 'High', 'medium': 'Medium', 'low': 'Low'}
        return mapping.get(severity, 'Medium')
    
    
    async def run_mythril_on_all_contracts(self, contract_file: Path) -> List[AnalysisFinding]:
        """Run Mythril on all contracts compiled from a single Solidity file"""
        findings = []
        artifacts_dir = self.workspace_dir / 'artifacts' / 'contracts'
        contract_subdir = artifacts_dir / f"{contract_file.name}"
        
        logger.info(f"Looking for all contracts in {contract_file.name}")
        
        if contract_subdir.exists():
            # Get all non-debug JSON artifacts for this contract file
            artifact_files = [f for f in contract_subdir.glob('*.json') if '.dbg.json' not in f.name]
            logger.info(f"Found {len(artifact_files)} contract artifacts: {[f.name for f in artifact_files]}")
            
            for artifact_file in artifact_files:
                contract_name = artifact_file.stem
                logger.info(f"Analyzing contract: {contract_name}")
                
                try:
                    output = await self.analyze_contract_artifact(artifact_file, contract_file)
                    if output and output.strip():
                        contract_findings = self.parse_mythril_output(output, contract_file, contract_name)
                        findings.extend(contract_findings)
                        logger.info(f"Found {len(contract_findings)} findings for {contract_name}")
                    else:
                        logger.info(f"No issues found for {contract_name}")
                        
                except Exception as e:
                    logger.warning(f"Failed to analyze contract {contract_name}: {e}")
        else:
            logger.warning(f"No artifacts found for {contract_file.name}")
            # Fallback to original single contract analysis
            output = await self.run_mythril_on_contract(contract_file)
            if output and output.strip():
                findings_from_output = self.parse_mythril_output(output, contract_file)
                findings.extend(findings_from_output)
        
        return findings
    
    async def analyze_contract_artifact(self, artifact_file: Path, original_file: Path) -> str:
        """Analyze a specific contract artifact with Mythril"""
        try:
            # Read the bytecode from artifact
            with open(artifact_file, 'r') as f:
                artifact_data = json.load(f)
            
            bytecode = artifact_data.get('bytecode')
            if not bytecode or bytecode == '0x' or len(bytecode) <= 10:
                logger.info(f"No valid bytecode in artifact {artifact_file.name}")
                return ""
            
            # Clean bytecode
            clean_bytecode = bytecode[2:] if bytecode.startswith('0x') else bytecode
            
            # Also try deployed bytecode if available
            deployed_bytecode_obj = artifact_data.get('deployedBytecode')
            if isinstance(deployed_bytecode_obj, dict):
                deployed_bytecode = deployed_bytecode_obj.get('object', '')
            elif isinstance(deployed_bytecode_obj, str):
                deployed_bytecode = deployed_bytecode_obj
            else:
                deployed_bytecode = ""
                
            if deployed_bytecode and len(deployed_bytecode) > len(bytecode):
                logger.info(f"Using deployed bytecode for {artifact_file.name}")
                clean_bytecode = deployed_bytecode[2:] if deployed_bytecode.startswith('0x') else deployed_bytecode
            
            logger.info(f"Analyzing {artifact_file.name} with bytecode length: {len(clean_bytecode)}")
            
            # Run Mythril on bytecode
            bytecode_commands = [
                ['myth', 'analyze', '--code', clean_bytecode, '--execution-timeout', '60', '-o', 'json'],
                ['myth', 'analyze', '--code', clean_bytecode, '--execution-timeout', '60'],
                ['myth', 'a', '--code', clean_bytecode, '--execution-timeout', '30']
            ]
            
            for i, cmd in enumerate(bytecode_commands):
                try:
                    logger.info(f"Mythril attempt {i+1} for {artifact_file.name}: {' '.join(cmd[:4])}...")
                    output = await self.run_command_with_results(cmd, timeout=90)
                    
                    if output and output.strip():
                        output_preview = output[:200].replace('\n', ' ')
                        logger.info(f"Mythril output for {artifact_file.name}: {output_preview}...")
                        
                        if "No issues were detected" in output or "The analysis was completed successfully" in output:
                            logger.info(f"Mythril completed analysis of {artifact_file.name} - no issues found")
                            return "No security issues found"
                        elif "issues" in output or any(indicator in output for indicator in ["SWC ID:", "====", "Exception", "External"]):
                            logger.info(f"Mythril found issues in {artifact_file.name}")
                            return output
                        else:
                            return output
                    
                except Exception as e:
                    logger.warning(f"Mythril command failed for {artifact_file.name}: {str(e)[:100]}")
                    continue
            
            return ""
            
        except Exception as e:
            logger.error(f"Error analyzing artifact {artifact_file}: {e}")
            return ""
    
    async def run_mythril_on_contract(self, contract_file: Path) -> str:
        """Run Mythril on a single contract using bytecode analysis when solc fails"""
        # First try bytecode analysis (more reliable on ARM systems)
        logger.info(f"Starting Mythril analysis for {contract_file}")
        bytecode_output = await self.try_mythril_bytecode_analysis(contract_file)
        if bytecode_output:
            logger.info("Mythril bytecode analysis successful")
            return bytecode_output
        logger.info("Bytecode analysis failed, trying source analysis...")
        
        # Fallback to source code analysis if bytecode analysis fails
        logger.info(f"Contract file path: {contract_file} (exists: {contract_file.exists()})")
        command_variants = [
            ['myth', 'analyze', str(contract_file), '--execution-timeout', '120'],  # Removed invalid -v4 flag
            ['myth', 'a', str(contract_file), '--execution-timeout', '120']
        ]
        
        for cmd in command_variants:
            try:
                output = await self.run_command_with_results(cmd, timeout=120)
                if output and output.strip() and "SolcInstallationError" not in output and "rosetta error" not in output:
                    logger.info(f"Mythril source analysis successful with command: {' '.join(cmd)}")
                    return output
            except Exception as e:
                logger.debug(f"Mythril command {' '.join(cmd)} failed: {e}")
                # If it's a solc or architecture error, skip to next variant
                if any(error in str(e).lower() for error in ["solcinstallationerror", "solc", "rosetta", "sigtrap"]):
                    continue
        
        return ""
    
    async def try_mythril_bytecode_analysis(self, contract_file: Path) -> str:
        """Try to analyze bytecode using compiled artifacts"""
        try:
            # Look for compiled artifacts
            artifacts_dir = self.workspace_dir / 'artifacts' / 'contracts'
            contract_name = contract_file.stem
            
            logger.info(f"Looking for artifacts in: {artifacts_dir}")
            logger.info(f"Artifacts dir exists: {artifacts_dir.exists()}")
            
            if artifacts_dir.exists():
                logger.info(f"Contents of artifacts dir: {list(artifacts_dir.rglob('*.json'))}")
            
            # Find the artifact file - improved matching logic
            artifact_file = None
            if artifacts_dir.exists():
                for artifact_path in artifacts_dir.rglob(f'*.json'):
                    logger.info(f"Checking artifact: {artifact_path}")
                    if '.dbg.json' not in artifact_path.name:
                        # Try multiple matching strategies:
                        # 1. Exact contract name match
                        # 2. Contract file name in path  
                        # 3. Any .json file in the contract's subdirectory
                        contract_subdir = artifacts_dir / f"{contract_file.name}"
                        if (contract_name.lower() in artifact_path.name.lower() or 
                            contract_file.name in str(artifact_path) or
                            artifact_path.parent == contract_subdir):
                            artifact_file = artifact_path
                            logger.info(f"Found matching artifact: {artifact_file}")
                            break
                
                # If still no match, try the first non-debug JSON file in the contract directory
                if not artifact_file:
                    contract_subdir = artifacts_dir / f"{contract_file.name}"
                    if contract_subdir.exists():
                        for json_file in contract_subdir.glob('*.json'):
                            if '.dbg.json' not in json_file.name:
                                artifact_file = json_file
                                logger.info(f"Using fallback artifact: {artifact_file}")
                                break
            
            if artifact_file and artifact_file.exists():
                # Read the bytecode from artifact
                with open(artifact_file, 'r') as f:
                    artifact_data = json.load(f)
                
                bytecode = artifact_data.get('bytecode')
                logger.info(f"Raw bytecode length: {len(bytecode) if bytecode else 0}")
                logger.info(f"Bytecode preview: {bytecode[:100] if bytecode else 'None'}...")
                
                # Check if bytecode is valid (not just constructor code)
                if bytecode and bytecode != '0x' and len(bytecode) > 10:
                    logger.info(f"Valid bytecode found for {contract_name}, length: {len(bytecode)}")
                    
                    # Create a temporary bytecode file (remove 0x prefix)
                    clean_bytecode = bytecode[2:] if bytecode.startswith('0x') else bytecode
                    bytecode_file = self.workspace_dir / f'{contract_name}_bytecode.bin'
                    bytecode_file.write_text(clean_bytecode)
                    
                    # Also try deployed bytecode if available
                    deployed_bytecode_obj = artifact_data.get('deployedBytecode')
                    deployed_bytecode = ""
                    
                    # Handle both string and object formats for deployedBytecode
                    if isinstance(deployed_bytecode_obj, dict):
                        deployed_bytecode = deployed_bytecode_obj.get('object', '')
                    elif isinstance(deployed_bytecode_obj, str):
                        deployed_bytecode = deployed_bytecode_obj
                    
                    if deployed_bytecode and len(deployed_bytecode) > len(bytecode):
                        logger.info(f"Using deployed bytecode (longer): {len(deployed_bytecode)} chars")
                        clean_bytecode = deployed_bytecode[2:] if deployed_bytecode.startswith('0x') else deployed_bytecode
                    
                    # Try direct bytecode analysis using --code parameter (avoids solc dependency)
                    # Use JSON output format for better parsing
                    logger.info(f"Starting bytecode analysis with clean_bytecode length: {len(clean_bytecode)}")
                    
                    # Validate bytecode before analysis
                    if len(clean_bytecode) < 20:
                        logger.warning(f"Bytecode too short for analysis: {len(clean_bytecode)} chars")
                        return ""
                    
                    bytecode_commands = [
                        ['myth', 'analyze', '--code', clean_bytecode, '--execution-timeout', '60', '-o', 'json'],
                        ['myth', 'analyze', '--code', clean_bytecode, '--execution-timeout', '60'],  # fallback to text
                        ['myth', 'a', '--code', clean_bytecode, '--execution-timeout', '30'],
                        ['myth', 'analyze', '--code', clean_bytecode[:1000]]  # Try truncated version
                    ]
                    
                    for i, cmd in enumerate(bytecode_commands):
                        try:
                            logger.info(f"Attempt {i+1}/{len(bytecode_commands)}: Trying command {' '.join(cmd[:4])}...")
                            output = await self.run_command_with_results(cmd, timeout=90)
                            logger.info(f"Command completed. Output length: {len(output) if output else 0}")
                            
                            if output and output.strip():
                                output_preview = output[:300].replace('\n', ' ')
                                logger.info(f"Mythril output preview: {output_preview}...")
                                
                                if "No issues were detected" in output or "The analysis was completed successfully" in output:
                                    logger.info("Mythril bytecode analysis completed - no issues found")
                                    return "No security issues found"
                                elif any(indicator in output for indicator in ["SWC ID:", "====", "Exception", "External", "issues", "vulnerability"]):
                                    logger.info("Mythril bytecode analysis found potential issues")
                                    return output
                                else:
                                    logger.info(f"Mythril output available but unclear format - returning anyway")
                                    return output
                            else:
                                logger.warning(f"Mythril command returned empty output")
                            
                        except Exception as e:
                            logger.warning(f"Bytecode command {i+1} failed: {str(e)[:100]}")
                            continue
                    
                    logger.info("All bytecode analysis attempts failed")
            else:
                logger.info(f"No compiled artifacts found for {contract_name}")
                logger.info(f"Searched in: {artifacts_dir}")
                if artifacts_dir.exists():
                    logger.info(f"Available files: {list(artifacts_dir.rglob('*'))}")
            
        except Exception as e:
            logger.error(f"Bytecode analysis failed for {contract_file.name}: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
        
        return ""
    
    def parse_mythril_text_output(self, output: str) -> List[dict]:
        """Parse Mythril text output to extract security findings"""
        issues = []
        
        # Check if analysis completed with no issues
        if "No issues were detected" in output or "Analysis complete" in output:
            return []
        
        # Split output into sections by looking for issue headers
        lines = output.split('\n')
        current_issue = {}
        in_issue_section = False
        
        for line in lines:
            line = line.strip()
            
            # Detect start of new issue section
            if line.startswith('====') and any(keyword in line for keyword in ['Exception', 'External', 'Integer', 'Unchecked', 'Transaction']):
                # Save previous issue if exists
                if current_issue:
                    issues.append(current_issue)
                
                # Start new issue
                current_issue = {
                    'title': line.replace('=', '').strip(),
                    'swc-id': 'Unknown',
                    'severity': 'Medium',
                    'description': '',
                    'function': 'unknown',
                    'lineno': None
                }
                in_issue_section = True
                
            elif in_issue_section and line:
                # Parse specific fields
                if line.startswith('SWC ID:'):
                    swc_id = line.split(':', 1)[1].strip()
                    current_issue['swc-id'] = swc_id
                    current_issue['title'] = f"SWC-{swc_id}"
                    
                elif line.startswith('Severity:'):
                    current_issue['severity'] = line.split(':', 1)[1].strip()
                    
                elif line.startswith('Function name:'):
                    current_issue['function'] = line.split(':', 1)[1].strip()
                    
                elif line.startswith('PC address:'):
                    current_issue['lineno'] = line.split(':', 1)[1].strip()
                    
                elif not line.startswith('Contract:') and not line.startswith('----'):
                    # Add to description
                    if current_issue['description']:
                        current_issue['description'] += ' '
                    current_issue['description'] += line
            
            # End of issue section
            elif line.startswith('----'):
                in_issue_section = False
        
        # Add final issue
        if current_issue:
            issues.append(current_issue)
        
        # Filter out empty issues
        return [issue for issue in issues if issue.get('swc-id') != 'Unknown' or issue.get('description')]
        
        return issues
    
    
    
    def parse_mythril_output(self, output: str, contract_file: Path, contract_name: str = None) -> List[AnalysisFinding]:
        """Parse Mythril output with improved error handling for multiple formats"""
        findings = []
        try:
            logger.info(f"Parsing Mythril output, length: {len(output)}, starts with: {output[:50]}...")
            
            # Handle special cases first
            if "No issues were detected" in output or "The analysis was completed successfully" in output:
                logger.info("Mythril found no security issues")
                return []
            
            # Try to parse JSON output first
            issues = []
            output_stripped = output.strip()
            
            if output_stripped.startswith('{') or output_stripped.startswith('['):
                try:
                    results = json.loads(output_stripped)
                    logger.info(f"Successfully parsed JSON output: {type(results)}")
                    if isinstance(results, dict):
                        issues = results.get('issues', results.get('results', []))
                    elif isinstance(results, list):
                        issues = results
                    logger.info(f"Extracted {len(issues)} issues from JSON")
                except json.JSONDecodeError as e:
                    logger.warning(f"JSON parse failed: {e}, falling back to text parsing")
                    # Fall back to text parsing
                    issues = self.parse_mythril_text_output(output)
            else:
                logger.info("Parsing as text output")
                # Handle text output directly
                issues = self.parse_mythril_text_output(output)
            
            # Convert issues to findings
            for issue in issues:
                swc_id = issue.get('swc-id', 'Unknown')
                title = issue.get('title', f'SWC-{swc_id}' if swc_id != 'Unknown' else 'Security Issue')
                
                findings.append(AnalysisFinding(
                    tool='mythril',
                    contract=contract_name or contract_file.stem,
                    category='security',
                    severity=self.map_mythril_severity(issue.get('severity', 'Medium')),
                    title=title,
                    description=issue.get('description', ''),
                    location={
                        'file': str(contract_file),
                        'line': issue.get('lineno'),
                        'function': issue.get('function', 'unknown')
                    },
                    recommendation=f"Review SWC-{swc_id} vulnerability: {title}"
                ))
            
            logger.info(f"Mythril parsed {len(findings)} security findings from output")
                
        except Exception as e:
            logger.warning(f"Could not parse Mythril output for {contract_file.name}: {e}")
            logger.debug(f"Mythril raw output: {output[:200]}...")
        
        return findings
    
    async def generate_report(self, result: AnalysisResult, output_dir: Path) -> Path:
        """Generate JSON report"""
        # Ensure output directory exists and is writable
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        report_filename = f"analysis_{self.analysis_id}_{timestamp}.json"
        report_path = output_dir / report_filename
        
        # Log the absolute paths for debugging
        logger.info(f"Output directory: {output_dir.absolute()}")
        logger.info(f"Report will be written to: {report_path.absolute()}")
        
        await ReportGenerator.generate_json_report(result, report_path)
        logger.info(f"Report generated: {report_path}")
        
        return report_path
    
    async def cleanup(self):
        """Clean up workspace"""
        if self.workspace_dir and self.workspace_dir.exists():
            FileHandler.cleanup_workspace(self.workspace_dir)
            logger.info(f"🧹 Workspace cleaned")

# CLI Interface
async def main():
    """Main CLI interface"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analyze.py <input_file_or_directory> [output_directory]")
        print("Example: python analyze.py test-contracts/SimpleToken.sol reports/")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./reports"
    
    try:
        engine = SolidityAnalysisEngine()
        result = await engine.analyze_file(input_path, output_dir)
        
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        logger.error(f"CLI execution failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
