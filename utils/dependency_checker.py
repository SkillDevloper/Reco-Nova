import subprocess
import sys
import importlib
from colorama import Fore, Style
from utils.helpers import print_info, print_success, print_error, print_warning

class DependencyChecker:
    REQUIRED_PACKAGES = {
        'requests': '2.31.0',
        'colorama': '0.4.6',
        'urllib3': '2.0.0',
        'tqdm': '4.66.0',
        'jinja2': '3.1.0'
    }
    
    @classmethod
    def check_and_install_dependencies(cls):
        print_info("Checking dependencies...")
        
        missing_packages = []
        outdated_packages = []
        
        for package, min_version in cls.REQUIRED_PACKAGES.items():
            if cls._is_package_installed(package, min_version):
                print_success(f"{package} (>= {min_version}) ✓")
            else:
                if cls._is_package_installed(package):
                    outdated_packages.append((package, min_version))
                    print_warning(f"{package} needs update (>= {min_version})")
                else:
                    missing_packages.append((package, min_version))
                    print_warning(f"{package} not installed")
        
        if missing_packages or outdated_packages:
            print_info("Installing/updating dependencies...")
            
            all_packages = missing_packages + outdated_packages
            success = cls._install_packages(all_packages)
            
            if success:
                print_success("All dependencies installed/updated successfully!")
            else:
                print_error("Failed to install some dependencies. Please install manually:")
                print_error("pip install -r requirements.txt")
                return False
        
        return True
    
    @classmethod
    def _is_package_installed(cls, package_name, min_version=None):
        try:
            module = importlib.import_module(package_name)
            if min_version:
                import pkg_resources
                installed_version = pkg_resources.get_distribution(package_name).version
                return cls._version_satisfies(installed_version, min_version)
            return True
        except ImportError:
            return False
        except:
            return False
    
    @classmethod
    def _version_satisfies(cls, installed, required):
        try:
            from packaging import version
            return version.parse(installed) >= version.parse(required)
        except ImportError:
            try:
                installed_parts = [int(x) for x in installed.split('.')]
                required_parts = [int(x) for x in required.split('.')]
                
                for i in range(max(len(installed_parts), len(required_parts))):
                    installed_val = installed_parts[i] if i < len(installed_parts) else 0
                    required_val = required_parts[i] if i < len(required_parts) else 0
                    
                    if installed_val > required_val:
                        return True
                    elif installed_val < required_val:
                        return False
                
                return True
            except:
                return True
    
    @classmethod
    def _install_packages(cls, packages):
        try:
            package_specs = []
            for package, version in packages:
                package_specs.append(f"{package}>={version}")
            
            cmd = [sys.executable, "-m", "pip", "install", "--upgrade"] + package_specs
            
            print_info(f"Running: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            return True
            
        except subprocess.CalledProcessError as e:
            print_error(f"Installation failed: {e.stderr}")
            return False
        except Exception as e:
            print_error(f"Error during installation: {e}")
            return False
    
    @classmethod
    def check_external_tools(cls):
        print_info("Checking external tools...")
        
        tools = {
            'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
            'httpx': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'gowitness': 'go install -v github.com/sensepost/gowitness@latest'
        }
        
        missing_tools = []
        
        for tool, install_cmd in tools.items():
            if cls._is_tool_available(tool):
                print_success(f"{tool} ✓")
            else:
                missing_tools.append((tool, install_cmd))
                print_warning(f"{tool} not found (optional)")
        
        if missing_tools:
            print_warning("Some external tools are not installed (optional but recommended):")
            for tool, install_cmd in missing_tools:
                print_warning(f"  {tool}: {install_cmd}")
            print_warning("Note: These tools require Go to be installed")
        
        return len(missing_tools) == 0
    
    @classmethod
    def _is_tool_available(cls, tool_name):
        try:
            result = subprocess.run(
                [tool_name, '-h'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0 or tool_name in result.stdout.lower()
        except:
            return False
