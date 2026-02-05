#!/usr/bin/env python3
"""
LOLBins Reference - Database Updater
=====================================
Downloads and updates the LOLBins database from official sources:
- Windows: LOLBAS Project (https://github.com/LOLBAS-Project/LOLBAS)
- Linux: GTFOBins (https://github.com/GTFOBins/GTFOBins.github.io)

Usage:
    python update_db.py

Requirements:
    pip install requests pyyaml
"""

import os
import yaml
import json
import requests
import zipfile
import io
import sys
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

# Local folder for Linux (GTFOBins) - requires git clone first
GTFOBINS_LOCAL_PATH = os.path.join("GTFOBins.github.io", "_gtfobins")

# URL for Windows (LOLBAS) - Downloaded as ZIP for speed
LOLBAS_ZIP_URL = "https://github.com/LOLBAS-Project/LOLBAS/archive/refs/heads/master.zip"

# Output file
OUTPUT_FILE = os.path.join("js", "data.js")

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def print_banner():
    """Print a nice banner"""
    print("""
╔═══════════════════════════════════════════════════════════╗
║  🔧 LOLBins Reference - Database Updater                  ║
║  Updates from LOLBAS & GTFOBins official repositories     ║
╚═══════════════════════════════════════════════════════════╝
    """)

def parse_front_matter_lenient(content):
    """Parse YAML Front Matter even if closing --- is missing"""
    try:
        content = content.lstrip('\ufeff')  # Remove BOM headers
        parts = content.split('---')
        if len(parts) >= 2:
            return yaml.safe_load(parts[1])
    except Exception:
        pass
    return None

# ============================================================================
# LINUX (GTFOBins) FETCHER
# ============================================================================

def fetch_gtfobins_local():
    """Read Linux binaries from local folder (requires git clone)"""
    print(f"🐧 [Linux] Checking local folder: {GTFOBINS_LOCAL_PATH}")
    
    # Check if user has cloned the repo
    if not os.path.exists(GTFOBINS_LOCAL_PATH):
        print("❌ ERROR: GTFOBins folder not found!")
        print("")
        print("   To fix this, run the following command:")
        print("   ┌─────────────────────────────────────────────────────────────┐")
        print("   │ git clone https://github.com/GTFOBins/GTFOBins.github.io.git│")
        print("   └─────────────────────────────────────────────────────────────┘")
        print("")
        return []

    bins = []
    
    # Category mapping: GTFOBins -> LOLBins Reference
    category_map = {
        "shell": "shell",
        "command": "execute",
        "reverse-shell": "reverse-shell",
        "bind-shell": "reverse-shell",
        "file-upload": "file-write",
        "file-download": "file-read",
        "file-write": "file-write",
        "file-read": "file-read",
        "sudo": "sudo",
        "suid": "suid",
        "capabilities": "capabilities",
        "limited-suid": "suid",
        "library-load": "execute"
    }

    files = [f for f in os.listdir(GTFOBINS_LOCAL_PATH) if not f.startswith(".")]
    total_files = len(files)
    print(f"   ↳ Found {total_files} files. Parsing...")

    count = 0
    for i, filename in enumerate(files):
        filepath = os.path.join(GTFOBINS_LOCAL_PATH, filename)
        if os.path.isdir(filepath):
            continue

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            if not content.strip().startswith('---'):
                continue
            
            data = parse_front_matter_lenient(content)
            if not data or 'functions' not in data:
                continue

            binary_name = filename.replace('.md', '')
            
            new_bin = {
                "name": binary_name,
                "description": data.get('description', f"Unix binary {binary_name}."),
                "categories": [],
                "commands": [],
                "mitre": {
                    "technique": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "url": "https://attack.mitre.org/techniques/T1059/"
                },
                "detection": [
                    f"Monitor execution of {binary_name}",
                    "Check for unusual command-line arguments",
                    "Monitor file system access patterns"
                ],
                "references": [
                    {
                        "name": "GTFOBins",
                        "url": f"https://gtfobins.github.io/gtfobins/{binary_name}/"
                    }
                ]
            }

            for func_name, examples in data.get('functions', {}).items():
                my_cat = category_map.get(func_name, "execute")
                if my_cat not in new_bin["categories"]:
                    new_bin["categories"].append(my_cat)
                
                for example in examples:
                    code = example.get('code', '')
                    # Replace placeholders with realistic examples
                    code = code.replace("LFILE=file_to_read", "LFILE=/etc/shadow")
                    code = code.replace("LFILE=file_to_write", "LFILE=/tmp/evil.sh")
                    code = code.replace("export LFILE=", "LFILE=")
                    
                    desc = example.get('description', func_name.upper())
                    new_bin["commands"].append({
                        "label": f"{func_name.upper()}: {desc}",
                        "code": code
                    })
            
            bins.append(new_bin)
            count += 1
            
            # Progress indicator
            if (i + 1) % 50 == 0:
                print(f"   ↳ Processed {i + 1}/{total_files}...")
            
        except Exception as e:
            continue

    print(f"✅ [Linux] Success! Parsed {count} binaries from disk.")
    return bins

# ============================================================================
# WINDOWS (LOLBAS) FETCHER
# ============================================================================

def fetch_lolbas_remote():
    """Download Windows binaries (LOLBAS) from the Internet (ZIP)"""
    print("🪟 [Windows] Downloading LOLBAS Repository...")
    
    try:
        response = requests.get(LOLBAS_ZIP_URL, timeout=30)
        response.raise_for_status()
        
        z = zipfile.ZipFile(io.BytesIO(response.content))
        bins = []
        
        yml_files = [f for f in z.namelist() if f.endswith('.yml') and '/yml/' in f]
        total_files = len(yml_files)
        print(f"   ↳ Found {total_files} YAML files. Parsing...")
        
        for i, filename in enumerate(yml_files):
            try:
                with z.open(filename) as f:
                    content = yaml.safe_load(f)
                    if not content:
                        continue
                    
                    new_bin = {
                        "name": content.get('Name', 'Unknown'),
                        "description": content.get('Description', 'No description available'),
                        "categories": [],
                        "commands": [],
                        "mitre": {
                            "technique": "",
                            "name": "",
                            "url": ""
                        },
                        "detection": [],
                        "references": []
                    }
                    
                    # Process commands
                    for cmd in content.get('Commands', []):
                        cat = cmd.get('Category', '').lower().replace(' ', '-')
                        
                        # Normalize categories
                        if cat == 'ads':
                            cat = 'execute'
                        if cat == 'reconnaissance':
                            cat = 'recon'
                        
                        if cat and cat not in new_bin['categories']:
                            new_bin['categories'].append(cat)
                        
                        new_bin['commands'].append({
                            "label": cmd.get('Description', 'Command'),
                            "code": cmd.get('Command', '')
                        })
                        
                        # Get MITRE info from first command that has it
                        if not new_bin['mitre']['technique'] and cmd.get('MitreID'):
                            mitre_id = cmd.get('MitreID')
                            new_bin['mitre']['technique'] = mitre_id
                            new_bin['mitre']['name'] = cmd.get('MitreName', '')
                            # Replace dot (.) with slash (/) for MITRE URL to work correctly
                            mitre_url_id = mitre_id.replace('.', '/')
                            new_bin['mitre']['url'] = f"https://attack.mitre.org/techniques/{mitre_url_id}/"
                    
                    # Process detection
                    for det in content.get('Detection', []):
                        if det.get('Sigma'):
                            new_bin['detection'].append(f"Sigma Rule: {det.get('Sigma')}")
                        if det.get('IOC'):
                            new_bin['detection'].append(det.get('IOC'))
                    
                    if not new_bin['detection']:
                        new_bin['detection'] = [
                            f"Monitor execution of {new_bin['name']}",
                            "Check for suspicious command-line arguments"
                        ]
                    
                    # Process references
                    for ref in content.get('Resources', []):
                        if isinstance(ref, str):
                            new_bin['references'].append({
                                "name": "Reference",
                                "url": ref
                            })
                    
                    # Add LOLBAS reference
                    safe_name = new_bin['name'].replace('.exe', '').replace('.dll', '')
                    new_bin['references'].append({
                        "name": "LOLBAS",
                        "url": f"https://lolbas-project.github.io/lolbas/Binaries/{safe_name}/"
                    })
                    
                    bins.append(new_bin)
                    
            except Exception:
                continue
        
        print(f"✅ [Windows] Success! Parsed {len(bins)} binaries from web.")
        return bins
        
    except requests.RequestException as e:
        print(f"❌ [Windows] Network Error: {e}")
        return []
    except Exception as e:
        print(f"❌ [Windows] Error: {e}")
        return []

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    print_banner()
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)
    
    # 1. Fetch Data
    linux_data = fetch_gtfobins_local()
    windows_data = fetch_lolbas_remote()
    
    if not linux_data and not windows_data:
        print("")
        print("❌ No data found. Update aborted.")
        sys.exit(1)

    # 2. Combine Data
    final_data = {
        "windows": windows_data,
        "linux": linux_data
    }
    
    # 3. Ensure output directory exists
    os.makedirs("js", exist_ok=True)
    
    # 4. Generate JavaScript file
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    js_content = f"""// LOLBins Reference Database
// Auto-generated: {timestamp}
// Windows: {len(windows_data)} binaries | Linux: {len(linux_data)} binaries
// Total: {len(windows_data) + len(linux_data)} binaries
// 
// Sources:
// - LOLBAS: https://github.com/LOLBAS-Project/LOLBAS
// - GTFOBins: https://github.com/GTFOBins/GTFOBins.github.io

const LOLBinsData = {json.dumps(final_data, indent=2, ensure_ascii=False)};
"""
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(js_content)
    
    # 5. Print summary
    print("")
    print("-" * 50)
    print("🎉 DATABASE UPDATE COMPLETE!")
    print("-" * 50)
    print(f"📄 Output: {OUTPUT_FILE}")
    print(f"📊 Statistics:")
    print(f"   • Windows (LOLBAS): {len(windows_data)} binaries")
    print(f"   • Linux (GTFOBins): {len(linux_data)} binaries")
    print(f"   • Total: {len(windows_data) + len(linux_data)} binaries")
    print("")
    print("✨ You can now open index.html to see the updated data!")
    print("")

if __name__ == "__main__":
    main()
