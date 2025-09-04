import shutil
import tempfile
from pathlib import Path
from typing import List

class FileHandler:
    @staticmethod
    def create_temp_workspace(prefix: str = "analysis-") -> Path:
        """Create temporary workspace directory"""
        workspace = Path(tempfile.mkdtemp(prefix=prefix))
        return workspace
    
    @staticmethod
    def cleanup_workspace(workspace_path: Path):
        """Clean up temporary workspace"""
        if workspace_path.exists():
            shutil.rmtree(workspace_path, ignore_errors=True)
    
    @staticmethod
    def find_solidity_files(directory: Path) -> List[Path]:
        """Find all Solidity files in directory recursively"""
        return list(directory.rglob('*.sol'))
    
    @staticmethod
    def ensure_directory(path: Path):
        """Ensure directory exists"""
        path.mkdir(parents=True, exist_ok=True)
    
    @staticmethod
    def copy_input_to_workspace(input_path: Path, workspace: Path) -> List[Path]:
        """Copy input files to workspace and return contract files"""
        contracts_dir = workspace / "contracts"
        contracts_dir.mkdir(exist_ok=True)
        
        if input_path.is_file():
            if input_path.suffix == '.sol':
                # Single Solidity file
                dest = contracts_dir / input_path.name
                shutil.copy2(input_path, dest)
                return [dest]
            else:
                raise ValueError(f"Unsupported file type: {input_path.suffix}")
        
        elif input_path.is_dir():
            # Directory - copy all .sol files
            sol_files = []
            for sol_file in input_path.rglob('*.sol'):
                dest = contracts_dir / sol_file.name
                shutil.copy2(sol_file, dest)
                sol_files.append(dest)
            return sol_files
        
        else:
            raise ValueError(f"Input path does not exist: {input_path}")
