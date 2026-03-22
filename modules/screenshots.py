import subprocess
import os
from utils.helpers import check_tool_installed, print_info, print_success, print_error, print_warning

class ScreenshotCapture:
    def __init__(self, domain):
        self.domain = domain
        self.live_hosts_file = os.path.join("output", "live_hosts.txt")
        self.screenshot_dir = os.path.join("output", "screenshots")
        
        if not os.path.exists(self.screenshot_dir):
            os.makedirs(self.screenshot_dir)
    
    def capture(self):
        print_info("Capturing screenshots...")
        
        if not os.path.exists(self.live_hosts_file):
            print_error("Live hosts file not found. Run live host detection first.")
            return []
        
        screenshots_taken = []
        
        if check_tool_installed('gowitness'):
            print_info("Using gowitness for screenshot capture...")
            screenshots_taken = self._run_gowitness()
        elif check_tool_installed('aquatone'):
            print_info("Using aquatone for screenshot capture...")
            screenshots_taken = self._run_aquatone()
        else:
            print_warning("No screenshot tools found.")
            print_info("Install gowitness: go install -v github.com/sensepost/gowitness@latest")
            print_info("Or install aquatone: go get -u github.com/michenriksen/aquatone")
            return []
        
        print_success(f"Captured {len(screenshots_taken)} screenshots")
        return screenshots_taken
    
    def _run_gowitness(self):
        try:
            cmd = [
                'gowitness', 
                'file', 
                '-f', self.live_hosts_file,
                '-d', self.screenshot_dir,
                '--disable-logging'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800
            )
            
            if result.returncode == 0:
                screenshots = []
                for file in os.listdir(self.screenshot_dir):
                    if file.endswith('.png'):
                        screenshots.append(os.path.join(self.screenshot_dir, file))
                return screenshots
            else:
                print_error(f"gowitness failed: {result.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            print_error("gowitness timed out")
            return []
        except FileNotFoundError:
            return []
        except Exception as e:
            print_error(f"Error running gowitness: {e}")
            return []
    
    def _run_aquatone(self):
        try:
            temp_dir = os.path.join("output", "aquatone_temp")
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
            
            cmd = [
                'aquatone',
                '-scan',
                '-ports', '80,443,8080,8443',
                '-out', temp_dir,
                '-t', '20'
            ]
            
            with open(self.live_hosts_file, 'r') as f:
                hosts = f.read().strip().split('\n')
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(input='\n'.join(hosts), timeout=1800)
            
            if process.returncode == 0:
                screenshots = []
                aquatone_screenshots = os.path.join(temp_dir, "aquatone_screenshots")
                
                if os.path.exists(aquatone_screenshots):
                    for file in os.listdir(aquatone_screenshots):
                        if file.endswith('.png'):
                            old_path = os.path.join(aquatone_screenshots, file)
                            new_path = os.path.join(self.screenshot_dir, file)
                            os.rename(old_path, new_path)
                            screenshots.append(new_path)
                
                return screenshots
            else:
                print_error(f"aquatone failed: {stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            print_error("aquatone timed out")
            return []
        except FileNotFoundError:
            return []
        except Exception as e:
            print_error(f"Error running aquatone: {e}")
            return []
