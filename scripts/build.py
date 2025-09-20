#!/usr/bin/env python3
"""
Build script for Python Lambda functions
"""
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


def main():
    """Main build function"""
    project_root = Path(__file__).parent.parent
    src_dir = project_root / "src"
    build_dir = project_root / "build"

    # Create build directory
    build_dir.mkdir(exist_ok=True)

    # Get all function directories
    functions = [d for d in src_dir.iterdir() if d.is_dir()]

    print(f"Building Lambda functions: {[f.name for f in functions]}")

    for function_dir in functions:
        function_name = function_dir.name
        zip_path = build_dir / f"{function_name}.zip"

        print(f"Building {function_name}...")

        # Create temporary directory for packaging
        temp_dir = build_dir / f"temp_{function_name}"
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        temp_dir.mkdir()

        # Copy function files
        shutil.copytree(function_dir, temp_dir, dirs_exist_ok=True)

        # Install dependencies if requirements.txt exists
        requirements_file = function_dir / "requirements.txt"
        if requirements_file.exists():
            print(f"Installing dependencies for {function_name}...")
            subprocess.run([
                sys.executable, "-m", "pip", "install",
                "-r", str(requirements_file),
                "-t", str(temp_dir),
                "--no-deps"
            ], check=True)

        # Create zip archive
        print(f"Creating {function_name}.zip...")
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(temp_dir)
                    zipf.write(file_path, arcname)

        # Clean up temporary directory
        shutil.rmtree(temp_dir)

        print(f"{function_name}.zip created ({zip_path.stat().st_size} bytes)")

    print("Build complete!")


if __name__ == "__main__":
    main()